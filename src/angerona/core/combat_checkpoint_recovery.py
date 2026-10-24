"""Recover narrowly proven no-effect interrupted Combat accounting.

This is not a general journal repair facility. No target is moved, removed or
executed; no signing authority is created; no historical journal byte changes.
The ordinary Combat reconciliation subsequently records an unapplied drill
intent. Completed firewall rollback recovery is an explicit stopped-app path
and requires fresh native absence evidence; it does not run during startup.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Callable

from angerona.modules.adversary_combat import JournalIntegrityError


class CheckpointRecoveryRefused(JournalIntegrityError):
    """The exact no-effect recovery contract could not be proved."""


def _read_regular(path: Path, maximum: int) -> bytes:
    from angerona.core.secure_store import _path_traverses_reparse

    if _path_traverses_reparse(path):
        raise CheckpointRecoveryRefused("Recovery input traverses a link or reparse point")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= maximum):
            raise CheckpointRecoveryRefused("Recovery input is not a bounded ordinary file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after, current = os.fstat(descriptor), path.stat(follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if (len(raw) != before.st_size or identity(before) != identity(after)
                or identity(after) != identity(current) or current.st_nlink != 1):
            raise CheckpointRecoveryRefused("Recovery input changed during inspection")
        return raw
    finally:
        os.close(descriptor)


def existing_installation(root: Path):
    """Open existing bus-derived authority in memory, without creating a key."""
    from angerona.modules.adversary_combat import AdversaryCombat, _JOURNAL_CONTEXT

    module = AdversaryCombat(Path(os.path.abspath(root)))
    key = bytes.fromhex(_read_regular(module.data_root / "bus.key", 256).decode("ascii").strip())
    if len(key) != 32:
        raise CheckpointRecoveryRefused("Existing bus authority is invalid")
    module._journal_key_cache = hmac.new(key, _JOURNAL_CONTEXT, hashlib.sha256).digest()
    return module


@dataclass
class _Plan:
    report: dict[str, Any]
    tail: dict[str, Any]
    inputs: dict[str, bytes]
    original: Path
    quarantine: Path


def _records(module, raw: bytes) -> list[dict]:
    from angerona.modules.adversary_combat import (
        _MAX_JOURNAL_LINE_BYTES, _MAX_JOURNAL_RECORDS,
    )

    lines = raw.splitlines()
    if not raw.endswith(b"\n") or not 1 <= len(lines) <= _MAX_JOURNAL_RECORDS:
        raise CheckpointRecoveryRefused("Journal is incomplete or exceeds its record budget")
    records: list[dict] = []
    previous = "0" * 64
    pending: dict[str, dict] = {}
    used: set[str] = set()
    for sequence, line in enumerate(lines, 1):
        record = module._bounded_authority_json(
            line, label="drill recovery journal record", max_bytes=_MAX_JOURNAL_LINE_BYTES,
        )
        core = {key: value for key, value in record.items() if key != "record_hmac"}
        if (not module._signed_journal_schema_valid(record)
                or record["sequence"] != sequence or record["previous_hmac"] != previous
                or not hmac.compare_digest(record["record_hmac"], module._record_hmac(core))):
            raise CheckpointRecoveryRefused("Journal chain authentication failed")
        action_id, phase = record.get("action_id"), record["record_type"]
        if not isinstance(action_id, str) or not re.fullmatch(r"act-[0-9a-f]{16}", action_id):
            raise CheckpointRecoveryRefused("Journal action identity is invalid")
        if phase == "intent":
            if (action_id in used or record.get("status") != "pending"
                    or record.get("reversible") is not True
                    or module._combat_action_from_record(record) is None):
                raise CheckpointRecoveryRefused("Journal contains ambiguous or irreversible work")
            used.add(action_id)
            pending[action_id] = record
        elif phase in {"commit", "failure"}:
            intent = pending.pop(action_id, None)
            if (intent is None or any(record.get(field) != intent.get(field)
                                      for field in ("action", "combat_id"))
                    or record.get("status") != ("applied" if phase == "commit" else "failed")
                    or (phase == "commit" and (
                        record.get("target") != intent.get("target")
                        or record.get("reversible") is not True))):
                raise CheckpointRecoveryRefused("Journal phase graph is inconsistent")
        else:
            # Recovery/undo histories need their own authority and postconditions.
            raise CheckpointRecoveryRefused("Journal contains other recovery or undo work")
        records.append(record)
        previous = record["record_hmac"]
    if pending != {records[-1]["action_id"]: records[-1]}:
        raise CheckpointRecoveryRefused("Journal does not contain exactly one trailing intent")
    return records


def _plan(module) -> _Plan:
    from angerona.modules.adversary_combat import _JOURNAL_CONTEXT, _MAX_JOURNAL_BYTES
    from angerona.core.secure_store import _path_traverses_reparse

    root = Path(os.path.abspath(module.data_root))
    inputs = {
        "bus.key": _read_regular(root / "bus.key", 256),
        "adversary_combat_actions.jsonl": _read_regular(module.receipt_path, _MAX_JOURNAL_BYTES),
        "secrets.dpapi": _read_regular(root / "secrets.dpapi", 1024 * 1024),
        "adversary_combat_recovery_witness.json": _read_regular(module.recovery_witness_path, 16 * 1024),
    }
    key = bytes.fromhex(inputs["bus.key"].decode("ascii").strip())
    if (len(key) != 32 or not isinstance(module._journal_key_cache, bytes)
            or not hmac.compare_digest(module._journal_key_cache,
                                       hmac.new(key, _JOURNAL_CONTEXT, hashlib.sha256).digest())):
        raise CheckpointRecoveryRefused("Existing journal authority does not match this installation")
    records = _records(module, inputs["adversary_combat_actions.jsonl"])
    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
    module._verify_recovery_witness(anchor)
    tail = records[-1]
    if (anchor["schema"] != 2 or anchor["last_journal_sequence"] != len(records) - 1
            or anchor["last_journal_hmac"] != tail["previous_hmac"]
            or anchor["active_action_id"] or anchor["active_challenge_sequence"]
            or anchor["consumed_terminal_sequence"] or anchor["challenge_counter"]):
        raise CheckpointRecoveryRefused("Not an exact one-record interrupted checkpoint")
    details = tail.get("details", {})
    binding = module._valid_quarantine_binding(tail)
    if (tail.get("record_type") != "intent" or tail.get("action") != "quarantine_file"
            or tail.get("trigger_module") != "Purple Remediation Guard"
            or tail.get("reversible") is not True or binding is None
            or details.get("move_strategy") != "rename"
            or type(details.get("source_link_count")) is not int
            or details["source_link_count"] != 1
            or details.get("file_identity") != details.get("source_identity")):
        raise CheckpointRecoveryRefused("Pending work is not an exact inert-marker quarantine intent")
    quarantine, original = binding
    if (original.parent != root / "drill-sandbox"
            or not re.fullmatch(r"_redteam_[a-z0-9_]+_[0-9a-f]{8}\.txt", original.name)
            or _path_traverses_reparse(original) or _path_traverses_reparse(quarantine)
            or os.path.lexists(quarantine)):
        raise CheckpointRecoveryRefused("Marker location is unsafe or quarantine destination is occupied")
    # Recheck protected inputs after decryption/validation; do not back up a
    # different credential generation from the one that supplied this anchor.
    if (inputs["secrets.dpapi"] != _read_regular(root / "secrets.dpapi", 1024 * 1024)
            or inputs["adversary_combat_recovery_witness.json"]
            != _read_regular(module.recovery_witness_path, 16 * 1024)):
        raise CheckpointRecoveryRefused("Protected recovery authority changed during inspection")
    token = hashlib.sha256(b"\0".join(
        [str(root).encode(), *(inputs[name] for name in sorted(inputs))]
    )).hexdigest()
    report = {"eligible": True, "journal_records": len(records),
              "checkpoint_sequence": anchor["last_journal_sequence"],
              "pending_action": "unapplied inert drill marker quarantine",
              "review_token": token, "host_actions_executed": 0, "rearmed": False}
    return _Plan(report, tail, inputs, original, quarantine)


def _verify_original(plan: _Plan, pinned) -> None:
    from angerona.shark.run_manifest import RED_TEAM_COMPREHENSIVE_PLAN

    details = plan.tail["details"]
    if (pinned.identity != details["file_identity"] or pinned.require_single_link() != 1
            or os.path.lexists(plan.quarantine)):
        raise CheckpointRecoveryRefused("Exact original marker or absent quarantine postcondition changed")
    descriptor = pinned.duplicate_custody_descriptor()
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not 0 < before.st_size <= 4096:
            raise CheckpointRecoveryRefused("Original marker exceeds its byte budget")
        stream.seek(0)
        raw = stream.read(4097)
        after = os.fstat(stream.fileno())
    if (len(raw) != before.st_size or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or hashlib.sha256(raw).hexdigest() != details.get("sha256")):
        raise CheckpointRecoveryRefused("Original marker content changed")
    if os.name != "nt":
        # Windows retains non-sharing file/directory handles; POSIX must also
        # prove that the still-open inode remains under its recorded name.
        named = plan.original.lstat()
        if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
            raise CheckpointRecoveryRefused("Original marker name changed identity")
    for entry in RED_TEAM_COMPREHENSIVE_PLAN:
        pattern = rf"_redteam_{re.escape(str(entry['marker_token']))}_[0-9a-f]{{8}}\.txt"
        expected = (
            "ANGERONA RED TEAM comprehensive drill — fixed inert marker.\n"
            f"Tactic: {entry['tactic']}\nTechnique: {entry['technique']}\n"
            "No named ATT&CK behavior was executed.\n"
        ).encode("utf-8")
        if re.fullmatch(pattern, plan.original.name) and raw == expected:
            return
    raise CheckpointRecoveryRefused("Original content is not a fixed comprehensive drill marker")


@contextmanager
def _held_original(plan: _Plan):
    from angerona.modules.adversary_combat import _PinnedFileMove

    with _PinnedFileMove(plan.original) as pinned:
        _verify_original(plan, pinned)
        yield pinned


def inspect_drill_checkpoint(module) -> dict[str, Any]:
    """Read-only eligibility. The review token is a snapshot, not authority."""
    plan = _plan(module)
    with _held_original(plan):
        return dict(plan.report)


def _backup(module, plan: _Plan) -> Path:
    from angerona.core.engine_transport import create_private_file, private_directory, verify_private

    directory = private_directory(module.data_root / ("combat-drill-recovery-" + secrets.token_hex(16)))
    for name, raw in plan.inputs.items():
        if name == "bus.key":
            continue  # Existing key is bound into the token, never duplicated.
        target = directory / name
        descriptor = create_private_file(target)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        verify_private(target)
        if _read_regular(target, 32 * 1024 * 1024) != raw:
            raise CheckpointRecoveryRefused("Pre-recovery backup did not verify")
    verify_private(directory, directory=True)
    return directory


def recover_drill_checkpoint(
    module, *, expected_token: str | None = None,
    before_commit: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Advance only a verified no-effect checkpoint; never perform an action.

    The runtime calls this before it executes any queued response work. A CLI
    caller must additionally prove the application is stopped and supply its
    inspected token. All writers share the installation journal lease.
    """
    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=False):
                plan = _plan(module)
                if expected_token is not None and not hmac.compare_digest(
                        expected_token, plan.report["review_token"]):
                    raise CheckpointRecoveryRefused("Recovery inputs changed; inspect again")
                with _held_original(plan) as pinned:
                    try:
                        directory = _backup(module, plan)
                    except (OSError, RuntimeError, ValueError) as exc:
                        raise CheckpointRecoveryRefused("Private recovery backup failed verification") from exc
                    current = _plan(module)
                    if not hmac.compare_digest(current.report["review_token"], plan.report["review_token"]):
                        raise CheckpointRecoveryRefused("Recovery inputs changed during backup")
                    _verify_original(plan, pinned)
                    module._assert_journal_session(module._active_journal_session())
                    if before_commit is not None:
                        try:
                            before_commit()
                        except (OSError, RuntimeError, ValueError) as exc:
                            raise CheckpointRecoveryRefused(str(exc)) from exc
                    module._advance_recovery_anchor(plan.tail)
                    module._invalidate_journal_cache()
                    records, legacy = module._read_journal(strict=True)
                    _verify_original(plan, pinned)
                    if legacy or len(records) != plan.report["journal_records"]:
                        raise CheckpointRecoveryRefused("Recovered checkpoint verification failed")
                    if _read_regular(module.receipt_path, 32 * 1024 * 1024) != plan.inputs["adversary_combat_actions.jsonl"]:
                        raise CheckpointRecoveryRefused("Recovery unexpectedly changed the journal")
                    return {**plan.report, "checkpoint_sequence": len(records),
                            "recovered": True, "backup_directory": str(directory)}


@dataclass
class _RollbackPlan:
    report: dict[str, Any]
    tail: dict[str, Any]
    inputs: dict[str, bytes]
    rule: str


def _native_firewall_rule_absent(rule: str) -> bool | None:
    """Query the exact native rule; only ERROR_FILE_NOT_FOUND proves absence.

    No localized console parsing, provider mutation or generated COM wrappers.
    A native COM call is point-in-time evidence and has no preemptive deadline.
    """
    if os.name != "nt":
        return None
    initialized = False
    policy = rules = native = None
    try:
        import pythoncom
        import pywintypes
        from win32com.client import dynamic

        pythoncom.CoInitializeEx(pythoncom.COINIT_APARTMENTTHREADED)
        initialized = True
        native = pythoncom.CoCreateInstance(
            pythoncom.MakeIID("{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}"),
            None, pythoncom.CLSCTX_INPROC_SERVER, pythoncom.IID_IDispatch,
        )
        policy = dynamic.Dispatch(native)
        rules = policy.Rules
        try:
            found = rules.Item(rule)
        except pywintypes.com_error as exc:
            # INetFwRules::Item documents this exact HRESULT for a missing rule.
            # IDispatch may wrap it in DISP_E_EXCEPTION with the native scode.
            code = int(exc.hresult) & 0xFFFFFFFF
            if code == 0x80020009 and exc.excepinfo:
                code = int(exc.excepinfo[5]) & 0xFFFFFFFF
            return True if code == 0x80070002 else None
        else:
            # A successful result, even a malformed one, never proves absence.
            found = None
            return False
    except Exception:
        return None
    finally:
        rules = policy = native = None
        if initialized:
            pythoncom.CoUninitialize()


def _rollback_records(module, raw: bytes) -> list[dict[str, Any]]:
    """Authenticate a deliberately small grammar, including all old history."""
    from angerona.modules.adversary_combat import (
        _MAX_JOURNAL_LINE_BYTES, _MAX_JOURNAL_RECORDS,
    )

    lines = raw.splitlines()
    if not raw.endswith(b"\n") or not 5 <= len(lines) <= _MAX_JOURNAL_RECORDS:
        raise CheckpointRecoveryRefused("Rollback journal is incomplete or exceeds its record budget")
    records = []
    previous = "0" * 64
    for sequence, line in enumerate(lines, 1):
        record = module._bounded_authority_json(
            line, label="rollback recovery journal record", max_bytes=_MAX_JOURNAL_LINE_BYTES,
        )
        core = {key: value for key, value in record.items() if key != "record_hmac"}
        if (not module._signed_journal_schema_valid(record)
                or record["sequence"] != sequence or record["previous_hmac"] != previous
                or not hmac.compare_digest(record["record_hmac"], module._record_hmac(core))):
            raise CheckpointRecoveryRefused("Rollback journal chain authentication failed")
        records.append(record)
        previous = record["record_hmac"]

    # Earlier work must be completely paired, known reversible actions. Other
    # undo/disposition/orphan histories need a separately reviewed recovery.
    prefix = records[:-5]
    if len(prefix) % 2:
        raise CheckpointRecoveryRefused("Rollback history contains unresolved work")
    used = set()
    action_fields = (
        "action_id", "combat_id", "action", "target", "applied_at",
        "reversible", "trigger_module", "trigger_ts",
    )
    for intent, terminal in zip(prefix[::2], prefix[1::2]):
        _rollback_intent(module, intent)
        if intent["action_id"] in used:
            raise CheckpointRecoveryRefused("Rollback history reuses an action identity")
        used.add(intent["action_id"])
        if (terminal.get("record_type") not in {"commit", "failure"}
                or any(terminal.get(key) != intent[key]
                       for key in ("action_id", "combat_id", "action"))):
            raise CheckpointRecoveryRefused("Rollback history has unpaired terminal work")
        if terminal["record_type"] == "commit":
            if (terminal.get("status") != "applied"
                    or any(terminal.get(key) != intent[key] for key in action_fields)
                    or not isinstance(terminal.get("details"), dict)
                    or any(terminal["details"].get(key) != value
                           for key, value in intent["details"].items())):
                raise CheckpointRecoveryRefused("Rollback history commit binding is inconsistent")
        elif (terminal.get("status") != "failed"
              or intent["action"] == "isolate_program"
              or terminal.get("error") != "orphaned intent had no observed postcondition"):
            raise CheckpointRecoveryRefused("Rollback history failure binding is inconsistent")
    intent, orphan, undo, undone, tail = records[-5:]
    _rollback_intent(module, intent)
    if intent["action_id"] in used or intent["action"] != "isolate_program":
        raise CheckpointRecoveryRefused("Rollback tail is not a unique program-isolation action")
    if (orphan.get("record_type") != "orphan" or orphan.get("status") != "orphaned"
            or orphan.get("rollback_state") != "pending"
            or any(orphan.get(key) != intent[key] for key in action_fields + ("details",))
            or orphan.get("mutation_started") is not None
            or orphan.get("rollback_error") is not None
            or orphan.get("error") != "program firewall postcondition failed"):
        raise CheckpointRecoveryRefused("Rollback orphan does not bind the exact failed program intent")
    if (undo.get("record_type") != "undo_intent" or undo.get("status") != "pending"
            or undone.get("record_type") != "undo_commit" or undone.get("status") != "undone"
            or not isinstance(undo.get("undo_id"), str)
            or not re.fullmatch(r"undo-[0-9a-f]{16}", undo["undo_id"])
            or any(undo.get(key) != undone.get(key)
                   for key in ("undo_id", "undo_of", "action", "bound_record_hmac"))
            or any(record.get("recovery") is not True or record.get("error") != ""
                   or record.get("undo_of") != intent["action_id"]
                   or record.get("action") != intent["action"]
                   or record.get("bound_record_hmac") != orphan["record_hmac"]
                   for record in (undo, undone))):
        raise CheckpointRecoveryRefused("Rollback lacks an exact successful recovery undo pair")
    if (tail.get("record_type") != "failure" or tail.get("status") != "failed"
            or any(tail.get(key) != intent[key] for key in ("action_id", "combat_id", "action"))
            or tail.get("error") != orphan["error"] + "; uncertain mutation rolled back"):
        raise CheckpointRecoveryRefused("Rollback tail is not the exact completed failure terminal")
    timestamps = [intent["intent_at"], orphan["orphaned_at"], undo["phase_at"],
                  undone["phase_at"], tail["failed_at"]]
    if (any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
            for value in timestamps) or timestamps != sorted(timestamps)):
        raise CheckpointRecoveryRefused("Rollback phase timestamps are inconsistent")
    return records


def _rollback_intent(module, record: dict[str, Any]) -> None:
    action = record.get("action")
    if (record.get("record_type") != "intent" or record.get("status") != "pending"
            or record.get("reversible") is not True
            or not re.fullmatch(r"act-[0-9a-f]{16}", str(record.get("action_id") or ""))
            or not re.fullmatch(r"combat-[0-9a-f]{12}|startup", str(record.get("combat_id") or ""))
            or not isinstance(action, str)
            or action not in {"activate_honeypots", "quarantine_file", "isolate_program"}
            or module._combat_action_from_record(record) is None):
        raise CheckpointRecoveryRefused("Rollback history contains an unfamiliar or invalid intent")
    details = record["details"]
    if not isinstance(details, dict) or not isinstance(record["target"], str) or not record["target"]:
        raise CheckpointRecoveryRefused("Rollback intent target binding is invalid")
    if action == "activate_honeypots":
        if record["target"] != "Smart Deception" or details.get("module") != "Smart Deception":
            raise CheckpointRecoveryRefused("Rollback history deception binding is invalid")
    elif action == "quarantine_file":
        if module._valid_quarantine_binding(record) is None:
            raise CheckpointRecoveryRefused("Rollback history quarantine binding is invalid")
    else:
        pid, birth, exe, rules = (details.get(key) for key in ("pid", "create_time", "exe", "rules"))
        if (type(pid) is not int or not 0 < pid <= 0xFFFFFFFF
                or type(birth) not in (float, int) or not math.isfinite(birth) or birth <= 0
                or not isinstance(exe, str) or not os.path.isabs(exe)
                or not os.path.isabs(record["target"])
                or os.path.normcase(os.path.abspath(exe)) != os.path.normcase(os.path.abspath(record["target"]))
                or not isinstance(rules, list) or len(rules) != 1
                or not isinstance(rules[0], str) or not module._valid_rule_set(action, rules)
                or not re.fullmatch(rf"Angerona-Combat-Program-{pid}-[0-9a-f]{{8}}", rules[0])):
            raise CheckpointRecoveryRefused("Rollback program, generation or managed rule binding is invalid")


def _rollback_plan(module) -> _RollbackPlan:
    from angerona.modules.adversary_combat import _JOURNAL_CONTEXT, _MAX_JOURNAL_BYTES

    root = Path(os.path.abspath(module.data_root))
    inputs = {
        "bus.key": _read_regular(root / "bus.key", 256),
        "adversary_combat_actions.jsonl": _read_regular(module.receipt_path, _MAX_JOURNAL_BYTES),
        "secrets.dpapi": _read_regular(root / "secrets.dpapi", 1024 * 1024),
        "adversary_combat_recovery_witness.json": _read_regular(module.recovery_witness_path, 16 * 1024),
    }
    key = bytes.fromhex(inputs["bus.key"].decode("ascii").strip())
    if (len(key) != 32 or not isinstance(module._journal_key_cache, bytes)
            or not hmac.compare_digest(module._journal_key_cache,
                                       hmac.new(key, _JOURNAL_CONTEXT, hashlib.sha256).digest())):
        raise CheckpointRecoveryRefused("Existing rollback authority does not match this installation")
    records = _rollback_records(module, inputs["adversary_combat_actions.jsonl"])
    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
    module._verify_recovery_witness(anchor)
    tail = records[-1]
    if (anchor["schema"] != 2 or anchor["last_journal_sequence"] != len(records) - 1
            or anchor["last_journal_hmac"] != tail["previous_hmac"]
            or anchor["active_action_id"] or anchor["active_challenge_sequence"]
            or anchor["active_challenge_nonce"] or anchor["consumed_terminal_sequence"]
            or anchor["challenge_counter"]):
        raise CheckpointRecoveryRefused("Not an exact one-terminal rollback checkpoint")
    for name, path in (("bus.key", root / "bus.key"),
                       ("secrets.dpapi", root / "secrets.dpapi"),
                       ("adversary_combat_recovery_witness.json", module.recovery_witness_path)):
        if inputs[name] != _read_regular(path, max(256, len(inputs[name]))):
            raise CheckpointRecoveryRefused("Rollback recovery authority changed during inspection")
    token = hashlib.sha256(b"rollback-checkpoint-v1\0" + b"\0".join(
        [str(root).encode(), *(inputs[name] for name in sorted(inputs))]
    )).hexdigest()
    rule = records[-5]["details"]["rules"][0]
    report = {"eligible": True, "journal_records": len(records),
              "checkpoint_sequence": anchor["last_journal_sequence"],
              "pending_action": "completed program-isolation rollback failure terminal",
              "review_token": token, "host_actions_executed": 0, "rearmed": False,
              "postcondition": "exact managed firewall rule absent"}
    return _RollbackPlan(report, tail, inputs, rule)


def _require_rollback_absence(plan: _RollbackPlan) -> None:
    if _native_firewall_rule_absent(plan.rule) is not True:
        raise CheckpointRecoveryRefused("Exact managed firewall rule absence is not proven")


def inspect_rollback_checkpoint(module) -> dict[str, Any]:
    """Read-only exact eligibility; no checkpoint, lease or backup is written."""
    plan = _rollback_plan(module)
    _require_rollback_absence(plan)
    current = _rollback_plan(module)
    if not hmac.compare_digest(plan.report["review_token"], current.report["review_token"]):
        raise CheckpointRecoveryRefused("Rollback recovery inputs changed during native observation")
    return dict(plan.report)


def _backup_rollback(module, plan: _RollbackPlan) -> Path:
    from angerona.core.engine_transport import create_private_file, private_directory, verify_private

    directory = private_directory(module.data_root / ("combat-rollback-recovery-" + secrets.token_hex(16)))
    for name, raw in plan.inputs.items():
        if name == "bus.key":
            continue
        target = directory / name
        descriptor = create_private_file(target)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        verify_private(target)
        if _read_regular(target, 32 * 1024 * 1024) != raw:
            raise CheckpointRecoveryRefused("Rollback recovery backup did not verify")
    verify_private(directory, directory=True)
    return directory


def recover_rollback_checkpoint(
    module, *, expected_token: str, before_commit: Callable[[], None],
) -> dict[str, Any]:
    """Explicit stopped-app accounting repair; no host action or journal write.

    A fresh native absence observation is required immediately before advancing
    existing authority. It cannot lease the OS firewall against external writers.
    """
    from angerona.core.secure_store import secret_transaction

    if not isinstance(expected_token, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_token):
        raise CheckpointRecoveryRefused("Rollback apply requires a reviewed inspection token")
    if not callable(before_commit):
        raise CheckpointRecoveryRefused("Rollback apply requires the stopped-application guard")
    before_commit()
    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=False):
                with secret_transaction(module.data_root):
                    plan = _rollback_plan(module)
                    if not hmac.compare_digest(expected_token, plan.report["review_token"]):
                        raise CheckpointRecoveryRefused("Rollback recovery inputs changed; inspect again")
                    _require_rollback_absence(plan)
                    try:
                        directory = _backup_rollback(module, plan)
                    except (OSError, RuntimeError, ValueError) as exc:
                        raise CheckpointRecoveryRefused("Private rollback recovery backup failed verification") from exc
                    current = _rollback_plan(module)
                    if not hmac.compare_digest(expected_token, current.report["review_token"]):
                        raise CheckpointRecoveryRefused("Rollback recovery inputs changed during backup")
                    _require_rollback_absence(current)
                    before_commit()
                    module._assert_journal_session(module._active_journal_session())
                    module._advance_recovery_anchor(current.tail)
                    module._invalidate_journal_cache()
                    records, legacy = module._read_journal(strict=True)
                    if (legacy or len(records) != plan.report["journal_records"]
                            or _read_regular(module.receipt_path, 32 * 1024 * 1024)
                            != plan.inputs["adversary_combat_actions.jsonl"]):
                        raise CheckpointRecoveryRefused("Rollback checkpoint final verification failed")
                    return {**plan.report, "checkpoint_sequence": len(records), "recovered": True,
                            "backup_directory": str(directory)}


_HOST_INCOMPLETE = "host isolation postcondition was incomplete"
_HOST_NO_EFFECT = (
    _HOST_INCOMPLETE
    + "; explicit stopped recovery observed both managed rules absent; no host action performed"
)
_PROGRAM_NO_EFFECT = (
    "program firewall postcondition failed"
    "; explicit stopped recovery observed the managed program rule absent; no host action performed"
)
_RECOVERY_ACTION_BINDINGS = (
    "action_id", "combat_id", "action", "target", "applied_at", "reversible",
    "trigger_module", "trigger_ts",
)


@dataclass
class _HostUndoPlan:
    report: dict[str, Any]
    records: list[dict[str, Any]]
    inputs: dict[str, bytes]
    rules: tuple[str, ...]


def _recovery_timestamp(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def _host_recovery_intent(module, record: dict[str, Any]) -> None:
    if (not all(_recovery_timestamp(record.get(key))
                for key in ("applied_at", "trigger_ts", "intent_at"))
            or not isinstance(record.get("trigger_module"), str) or not record["trigger_module"]
            or record["applied_at"] > record["intent_at"]):
        raise CheckpointRecoveryRefused("Recovery intent timestamps or trigger binding are invalid")
    if record.get("action") != "isolate_host":
        _rollback_intent(module, record)
        return
    details = record.get("details")
    rules = details.get("rules") if isinstance(details, dict) else None
    if (record.get("record_type") != "intent" or record.get("status") != "pending"
            or record.get("reversible") is not True
            or not re.fullmatch(r"act-[0-9a-f]{16}", str(record.get("action_id") or ""))
            or not re.fullmatch(r"combat-[0-9a-f]{12}", str(record.get("combat_id") or ""))
            or record.get("target") != "all remote network traffic"
            or not isinstance(rules, list) or len(rules) != 2
            or not all(isinstance(rule, str) for rule in rules)
            or not module._valid_rule_set("isolate_host", rules)
            or module._combat_action_from_record(record) is None):
        raise CheckpointRecoveryRefused("Host recovery intent/rule binding is invalid")


def _recovery_orphan(intent, orphan) -> None:
    expected = (_HOST_INCOMPLETE if intent["action"] == "isolate_host"
                else "program firewall postcondition failed")
    if (intent["action"] not in {"isolate_host", "isolate_program"}
            or orphan.get("record_type") != "orphan" or orphan.get("status") != "orphaned"
            or orphan.get("rollback_state") != "pending"
            or any(orphan.get(key) != intent[key] for key in _RECOVERY_ACTION_BINDINGS + ("details",))
            or orphan.get("mutation_started") is not None or orphan.get("rollback_error") is not None
            or orphan.get("error") != expected):
        raise CheckpointRecoveryRefused("Recovery orphan is not bound to its exact reversible intent")


def _recovery_undo(orphan, undo, phase: str, undo_id: str | None = None) -> None:
    if (undo.get("record_type") != phase
            or undo.get("status") != ("pending" if phase == "undo_intent" else "undone")
            or not re.fullmatch(r"undo-[0-9a-f]{16}", str(undo.get("undo_id") or ""))
            or (undo_id is not None and undo.get("undo_id") != undo_id)
            or undo.get("undo_of") != orphan["action_id"]
            or undo.get("action") != orphan["action"]
            or undo.get("bound_record_hmac") != orphan["record_hmac"]
            or undo.get("recovery") is not True or undo.get("error") != ""
            or not _recovery_timestamp(undo.get("phase_at"))):
        raise CheckpointRecoveryRefused("Recovery undo identity/orphan binding is invalid")


def _completed_native_termination(module, intent, terminal) -> tuple[int, int]:
    """Validate historical native completion, never authorize another process action."""
    from angerona.core.windows_process_lease import ProcessObjectIdentity, _image_path

    details, proof = intent.get("details"), terminal.get("details")
    if not isinstance(details, dict) or not isinstance(proof, dict):
        raise CheckpointRecoveryRefused("Completed termination lacks native custody proof")
    pid, birth, ticks = (details.get(key) for key in ("pid", "create_time", "native_birth_ticks"))
    name = details.get("name")
    if (intent.get("record_type") != "intent" or intent.get("status") != "pending"
            or intent.get("action") != "terminate_process" or intent.get("reversible") is not False
            or not re.fullmatch(r"act-[0-9a-f]{16}", str(intent.get("action_id") or ""))
            or not re.fullmatch(r"combat-[0-9a-f]{12}", str(intent.get("combat_id") or ""))
            or type(pid) is not int or not 0 < pid <= 0xFFFFFFFF
            or not _recovery_timestamp(birth) or type(ticks) is not int or not 0 < ticks < 2**64
            or type(details.get("native_pid")) is not int or details["native_pid"] != pid
            or details.get("process_custody") != "windows-retained-handle-v1"
            or not re.fullmatch(r"[0-9a-f]{32}", str(details.get("mutation_generation") or ""))
            or not isinstance(name, str) or not 1 <= len(name) <= 260
            or intent.get("target") != f"{name} ({pid})"
            or not isinstance(intent.get("trigger_module"), str) or not intent["trigger_module"]
            or not all(_recovery_timestamp(intent.get(key))
                       for key in ("applied_at", "intent_at", "trigger_ts"))
            or not birth <= intent["applied_at"] <= intent["intent_at"]
            or module._combat_action_from_record(intent) is None):
        raise CheckpointRecoveryRefused("Completed termination intent/generation binding is invalid")
    try:
        image = _image_path(details.get("exe"))
        if _image_path(details.get("native_image")) != image:
            raise ValueError("different image")
        observed_birth = ProcessObjectIdentity(pid, ticks, image).create_time
        if not _recovery_timestamp(observed_birth) or abs(observed_birth - birth) > 0.001:
            raise ValueError("different generation")
    except (TypeError, ValueError, RuntimeError) as exc:
        raise CheckpointRecoveryRefused("Completed termination native image/generation is invalid") from exc
    additions = {"postcondition_verified", "native_image_observation", "native_exit_code", "native_wait_signaled"}
    if (terminal.get("record_type") != "commit" or terminal.get("status") != "applied"
            or any(type(terminal.get(key)) is not type(intent[key]) or terminal.get(key) != intent[key]
                   for key in _RECOVERY_ACTION_BINDINGS)
            or set(proof) != set(details) | additions
            or module._canonical_record({key: proof[key] for key in details}) != module._canonical_record(details)
            or proof.get("postcondition_verified") is not True
            or proof.get("native_wait_signaled") is not True
            or proof.get("native_image_observation") != "before-termination"
            or type(proof.get("native_exit_code")) is not int
            or not 0 <= proof["native_exit_code"] <= 0xFFFFFFFF
            or not _recovery_timestamp(terminal.get("committed_at"))
            or terminal["committed_at"] < intent["intent_at"]):
        raise CheckpointRecoveryRefused("Completed termination terminal/native proof is inconsistent")
    return pid, ticks


def _closed_recovery_prefix(module, records, used_actions, used_undos,
                            *, allow_program_recovery: bool = False) -> None:
    """Admit only paired actions and exact completed reversible rollback groups."""
    index, terminated = 0, set()
    while index < len(records):
        intent = records[index]
        if allow_program_recovery and intent.get("action") == "terminate_process":
            if index + 1 >= len(records) or intent.get("action_id") in used_actions:
                raise CheckpointRecoveryRefused("Recovery history leaves or reuses termination work")
            identity = _completed_native_termination(module, intent, records[index + 1])
            if identity in terminated:
                raise CheckpointRecoveryRefused("Recovery history reuses a terminated native generation")
            terminated.add(identity)
            used_actions.add(intent["action_id"])
            index += 2
            continue
        _host_recovery_intent(module, intent)
        action_id = intent["action_id"]
        if action_id in used_actions or index + 1 >= len(records):
            raise CheckpointRecoveryRefused("Recovery history reuses an action or leaves work pending")
        used_actions.add(action_id)
        terminal = records[index + 1]
        if terminal.get("record_type") == "orphan":
            if index + 5 > len(records):
                raise CheckpointRecoveryRefused("Recovery history leaves a rollback pending")
            orphan, undo, undone, failure = records[index + 1:index + 5]
            _recovery_orphan(intent, orphan)
            _recovery_undo(orphan, undo, "undo_intent")
            _recovery_undo(orphan, undone, "undo_commit", undo["undo_id"])
            if undo["undo_id"] in used_undos:
                raise CheckpointRecoveryRefused("Recovery history reuses an undo identity")
            used_undos.add(undo["undo_id"])
            errors = {orphan["error"] + "; uncertain mutation rolled back"}
            if intent["action"] == "isolate_host":
                errors.add(_HOST_NO_EFFECT)
            elif allow_program_recovery and intent["action"] == "isolate_program":
                errors.add(_PROGRAM_NO_EFFECT)
            if (failure.get("record_type") != "failure" or failure.get("status") != "failed"
                    or any(failure.get(key) != intent[key] for key in ("action_id", "combat_id", "action"))
                    or failure.get("error") not in errors):
                raise CheckpointRecoveryRefused("Recovery history rollback terminal is inconsistent")
            stamps = [intent.get("intent_at"), orphan.get("orphaned_at"), undo["phase_at"],
                      undone["phase_at"], failure.get("failed_at")]
            if not all(_recovery_timestamp(stamp) for stamp in stamps) or stamps != sorted(stamps):
                raise CheckpointRecoveryRefused("Recovery history rollback timestamps are inconsistent")
            index += 5
            continue
        if any(terminal.get(key) != intent[key] for key in ("action_id", "combat_id", "action")):
            raise CheckpointRecoveryRefused("Recovery history terminal is not paired")
        if terminal.get("record_type") == "commit":
            if (terminal.get("status") != "applied"
                    or any(terminal.get(key) != intent[key] for key in _RECOVERY_ACTION_BINDINGS)
                    or not isinstance(terminal.get("details"), dict)
                    or any(terminal["details"].get(key) != value for key, value in intent["details"].items())):
                raise CheckpointRecoveryRefused("Recovery history commit binding is inconsistent")
        elif (terminal.get("record_type") != "failure" or terminal.get("status") != "failed"
              or intent["action"] not in {"activate_honeypots", "quarantine_file"}
              or terminal.get("error") != "orphaned intent had no observed postcondition"):
            raise CheckpointRecoveryRefused("Recovery history has unfamiliar terminal work")
        stamps = [intent.get("intent_at"), terminal.get(
            "committed_at" if terminal["record_type"] == "commit" else "failed_at")]
        if not all(_recovery_timestamp(stamp) for stamp in stamps) or stamps != sorted(stamps):
            raise CheckpointRecoveryRefused("Recovery history terminal timestamps are inconsistent")
        index += 2


def _authenticated_host_records(module, raw: bytes, *, reserve: int = 0) -> list[dict[str, Any]]:
    from angerona.modules.adversary_combat import (
        _MAX_JOURNAL_BYTES, _MAX_JOURNAL_LINE_BYTES, _MAX_JOURNAL_RECORDS,
    )

    lines = raw.splitlines()
    if (not raw.endswith(b"\n") or not 1 <= len(lines) <= _MAX_JOURNAL_RECORDS - reserve
            or len(raw) + reserve * (_MAX_JOURNAL_LINE_BYTES + 1) > _MAX_JOURNAL_BYTES):
        raise CheckpointRecoveryRefused("Host undo journal is incomplete or lacks closure capacity")
    records, previous = [], "0" * 64
    for sequence, line in enumerate(lines, 1):
        record = module._bounded_authority_json(line, label="host undo recovery record",
                                                max_bytes=_MAX_JOURNAL_LINE_BYTES)
        core = {key: value for key, value in record.items() if key != "record_hmac"}
        if (not module._signed_journal_schema_valid(record)
                or type(record.get("journal_version")) is not int or record["sequence"] != sequence
                or record["previous_hmac"] != previous
                or not hmac.compare_digest(record["record_hmac"], module._record_hmac(core))):
            raise CheckpointRecoveryRefused("Host undo full journal chain authentication failed")
        records.append(record)
        previous = record["record_hmac"]
    return records


def _host_undo_records(module, raw: bytes) -> list[dict[str, Any]]:
    records = _authenticated_host_records(module, raw, reserve=2)
    if len(records) < 3:
        raise CheckpointRecoveryRefused("Host undo journal lacks its exact three-record tail")
    used_actions, used_undos = set(), set()
    _closed_recovery_prefix(module, records[:-3], used_actions, used_undos)
    intent, orphan, undo = records[-3:]
    _host_recovery_intent(module, intent)
    if intent["action"] != "isolate_host" or intent["action_id"] in used_actions:
        raise CheckpointRecoveryRefused("Host undo tail is not one unique host-isolation intent")
    _recovery_orphan(intent, orphan)
    _recovery_undo(orphan, undo, "undo_intent")
    stamps = [intent.get("intent_at"), orphan.get("orphaned_at"), undo["phase_at"]]
    if (undo["undo_id"] in used_undos or not all(_recovery_timestamp(stamp) for stamp in stamps)
            or stamps != sorted(stamps) or time.time() < undo["phase_at"]):
        raise CheckpointRecoveryRefused("Host undo identity or timestamps are inconsistent")
    return records


def _program_closed_prefix(module, records, used_actions, used_undos) -> None:
    _closed_recovery_prefix(module, records, used_actions, used_undos, allow_program_recovery=True)


def _program_undo_records(module, raw: bytes) -> list[dict[str, Any]]:
    records = _authenticated_host_records(module, raw, reserve=2)
    if len(records) < 3:
        raise CheckpointRecoveryRefused("Program undo journal lacks its exact three-record tail")
    used_actions, used_undos = set(), set()
    _program_closed_prefix(module, records[:-3], used_actions, used_undos)
    intent, orphan, undo = records[-3:]
    _host_recovery_intent(module, intent)
    if intent["action"] != "isolate_program" or intent["action_id"] in used_actions:
        raise CheckpointRecoveryRefused("Program undo tail is not one unique program-isolation intent")
    _recovery_orphan(intent, orphan)
    _recovery_undo(orphan, undo, "undo_intent")
    stamps = [intent["intent_at"], orphan.get("orphaned_at"), undo["phase_at"]]
    if (undo["undo_id"] in used_undos or not all(_recovery_timestamp(stamp) for stamp in stamps)
            or stamps != sorted(stamps) or time.time() < undo["phase_at"]):
        raise CheckpointRecoveryRefused("Program undo identity or timestamps are inconsistent")
    return records


def _firewall_closure_records(module, plan: _HostUndoPlan, *, program: bool = False
                             ) -> tuple[list[dict[str, Any]], bytes]:
    """Authenticate the entire proposed closed history before its first write."""
    from angerona.modules.adversary_combat import _JOURNAL_VERSION, _MAX_JOURNAL_LINE_BYTES

    intent, orphan, undo = plan.records[-3:]
    action = "isolate_program" if program else "isolate_host"
    if intent["action"] != action:
        raise CheckpointRecoveryRefused("Firewall undo closure action scope differs")
    stamp = time.time()
    if not _recovery_timestamp(stamp) or stamp < undo["phase_at"]:
        raise CheckpointRecoveryRefused("Host undo closure clock is inconsistent")
    payloads = [{
        "record_type": "undo_commit", "undo_id": undo["undo_id"], "undo_of": undo["undo_of"],
        "action": action, "phase_at": stamp, "status": "undone", "error": "",
        "recovery": True, "bound_record_hmac": orphan["record_hmac"],
    }, {
        "record_type": "failure", "action_id": intent["action_id"], "combat_id": intent["combat_id"],
        "action": action, "failed_at": stamp, "status": "failed",
        "error": _PROGRAM_NO_EFFECT if program else _HOST_NO_EFFECT,
    }]
    sequence, previous, encoded = len(plan.records), undo["record_hmac"], b""
    for payload in payloads:
        sequence += 1
        core = {**payload, "journal_version": _JOURNAL_VERSION, "sequence": sequence,
                "previous_hmac": previous}
        record = {**core, "record_hmac": module._record_hmac(core)}
        previous = record["record_hmac"]
        encoded += module._canonical_record(record) + b"\n"
    # Reuse the existing single bounded pinned append for this small two-record
    # batch. No anchor advances until both durable records have been read back.
    if len(encoded) > _MAX_JOURNAL_LINE_BYTES + 1:
        raise CheckpointRecoveryRefused("Host undo closure batch exceeds its byte budget")
    records = _authenticated_host_records(module, plan.inputs["adversary_combat_actions.jsonl"] + encoded)
    (_program_closed_prefix if program else _closed_recovery_prefix)(module, records, set(), set())
    if module._ordered_pending_phases(records) or _pending_host_undos(records):
        raise CheckpointRecoveryRefused("Host undo proposed closure leaves pending work")
    return records, encoded


def _host_closure_records(module, plan: _HostUndoPlan) -> tuple[list[dict[str, Any]], bytes]:
    return _firewall_closure_records(module, plan)


def _program_closure_records(module, plan: _HostUndoPlan) -> tuple[list[dict[str, Any]], bytes]:
    return _firewall_closure_records(module, plan, program=True)


def _pending_host_undos(records) -> set[str]:
    return {record["undo_id"] for record in records if record["record_type"] == "undo_intent"} - {
        record["undo_id"] for record in records if record["record_type"] in {"undo_commit", "undo_failure"}}


def _firewall_undo_plan(module, *, program: bool = False) -> _HostUndoPlan:
    from angerona.modules.adversary_combat import _JOURNAL_CONTEXT, _MAX_JOURNAL_BYTES

    root = Path(os.path.abspath(module.data_root))
    inputs = {
        "bus.key": _read_regular(root / "bus.key", 256),
        "adversary_combat_actions.jsonl": _read_regular(module.receipt_path, _MAX_JOURNAL_BYTES),
        "secrets.dpapi": _read_regular(root / "secrets.dpapi", 1024 * 1024),
        "adversary_combat_recovery_witness.json": _read_regular(module.recovery_witness_path, 16 * 1024),
    }
    key = bytes.fromhex(inputs["bus.key"].decode("ascii").strip())
    if (len(key) != 32 or not isinstance(module._journal_key_cache, bytes)
            or not hmac.compare_digest(module._journal_key_cache,
                                       hmac.new(key, _JOURNAL_CONTEXT, hashlib.sha256).digest())):
        raise CheckpointRecoveryRefused("Host undo authority does not match this installation")
    records = (_program_undo_records if program else _host_undo_records)(
        module, inputs["adversary_combat_actions.jsonl"])
    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
    module._verify_recovery_witness(anchor)
    tail = records[-1]
    if (anchor["schema"] != 2 or anchor["last_journal_sequence"] != len(records) - 1
            or anchor["last_journal_hmac"] != tail["previous_hmac"]
            or anchor["active_action_id"] or anchor["active_challenge_sequence"]
            or anchor["active_challenge_nonce"] or anchor["consumed_terminal_sequence"]
            or anchor["challenge_counter"]):
        raise CheckpointRecoveryRefused("Host undo is not the exact one-record checkpoint gap")
    for name, path in (("bus.key", root / "bus.key"), ("secrets.dpapi", root / "secrets.dpapi"),
                       ("adversary_combat_actions.jsonl", module.receipt_path),
                       ("adversary_combat_recovery_witness.json", module.recovery_witness_path)):
        if inputs[name] != _read_regular(path, max(256, len(inputs[name]))):
            raise CheckpointRecoveryRefused("Host undo authority changed during inspection")
    context = b"stopped-program-undo-checkpoint-v1\0" if program else b"stopped-host-undo-checkpoint-v1\0"
    token = hashlib.sha256(context + b"\0".join(
        [str(root).encode(), *(inputs[name] for name in sorted(inputs))]
    )).hexdigest()
    rules = tuple(records[-3]["details"]["rules"])
    report = {"eligible": True, "journal_records": len(records),
              "checkpoint_sequence": anchor["last_journal_sequence"], "review_token": token,
              "pending_action": ("one interrupted recovery undo for an uncommitted program-isolation action"
                                 if program else "one interrupted recovery undo for an uncommitted host-isolation action"),
              "action_id": records[-3]["action_id"], "undo_id": tail["undo_id"],
              "rules": list(rules), "postcondition": ("the exact intent-bound managed program rule absent"
                                                     if program else "both exact intent-bound managed host rules absent"),
              "append_records": ["undo_commit", "failure"],
              "host_actions_executed": 0, "rearmed": False}
    return _HostUndoPlan(report, records, inputs, rules)


def _host_undo_plan(module) -> _HostUndoPlan:
    return _firewall_undo_plan(module)


def _program_undo_plan(module) -> _HostUndoPlan:
    return _firewall_undo_plan(module, program=True)


def _require_host_undo_absence(plan: _HostUndoPlan) -> None:
    if any(state is not True for state in [_native_firewall_rule_absent(rule) for rule in plan.rules]):
        raise CheckpointRecoveryRefused("Both exact managed host rules must be natively absent")


def _require_program_undo_absence(plan: _HostUndoPlan) -> None:
    if len(plan.rules) != 1 or _native_firewall_rule_absent(plan.rules[0]) is not True:
        raise CheckpointRecoveryRefused("The exact managed program rule must be natively absent")


def inspect_host_undo_checkpoint(module) -> dict[str, Any]:
    """Read-only eligibility; callers must separately keep the application stopped."""
    plan = _host_undo_plan(module)
    _require_host_undo_absence(plan)
    current = _host_undo_plan(module)
    if not hmac.compare_digest(plan.report["review_token"], current.report["review_token"]):
        raise CheckpointRecoveryRefused("Host undo inputs changed during native observation")
    return dict(plan.report)


def inspect_program_undo_checkpoint(module) -> dict[str, Any]:
    """Read-only program-only eligibility; separately keep every suite role stopped."""
    plan = _program_undo_plan(module)
    _require_program_undo_absence(plan)
    current = _program_undo_plan(module)
    if not hmac.compare_digest(plan.report["review_token"], current.report["review_token"]):
        raise CheckpointRecoveryRefused("Program undo inputs changed during native observation")
    return dict(plan.report)


def _backup_firewall_undo(module, plan: _HostUndoPlan, *, program: bool = False) -> Path:
    from angerona.core.engine_transport import create_private_file, private_directory, verify_private

    prefix = "combat-program-undo-recovery-" if program else "combat-host-undo-recovery-"
    directory = private_directory(module.data_root / (prefix + secrets.token_hex(16)))
    for name, raw in plan.inputs.items():
        if name == "bus.key":
            continue
        target = directory / name
        descriptor = create_private_file(target)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        verify_private(target)
        if _read_regular(target, 32 * 1024 * 1024) != raw:
            raise CheckpointRecoveryRefused("Host undo private backup failed verification")
    verify_private(directory, directory=True)
    return directory


def _backup_host_undo(module, plan: _HostUndoPlan) -> Path:
    return _backup_firewall_undo(module, plan)


def _backup_program_undo(module, plan: _HostUndoPlan) -> Path:
    return _backup_firewall_undo(module, plan, program=True)


def _recover_firewall_undo_checkpoint(module, *, expected_token: str,
                                      before_commit: Callable[[], None],
                                      program: bool = False) -> dict[str, Any]:
    """Explicit stopped accounting closure. Never perform a host undo or rearm.

    Interrupted stages stay held and need a new, separately reviewed recovery;
    this narrowly admitted initial shape is not a generic retry/startup bypass.
    Native absence and stopped-process guards are point-in-time observations.
    """
    from angerona.core.secure_store import secret_transaction

    label = "Program undo" if program else "Host undo"
    build_plan = _program_undo_plan if program else _host_undo_plan
    require_absence = _require_program_undo_absence if program else _require_host_undo_absence
    backup = _backup_program_undo if program else _backup_host_undo
    build_closure = _program_closure_records if program else _host_closure_records
    validate_prefix = _program_closed_prefix if program else _closed_recovery_prefix

    if not isinstance(expected_token, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_token):
        raise CheckpointRecoveryRefused(f"{label} apply requires a reviewed inspection token")
    if not callable(before_commit):
        raise CheckpointRecoveryRefused(f"{label} apply requires the stopped-application guard")
    before_commit()
    with module._receipt_lock:
        with module._journal_writer_lease():
            with module._pinned_journal_session(create=False):
                with secret_transaction(module.data_root):
                    plan = build_plan(module)
                    if not hmac.compare_digest(expected_token, plan.report["review_token"]):
                        raise CheckpointRecoveryRefused(f"{label} recovery inputs changed; inspect again")
                    require_absence(plan)
                    try:
                        directory = backup(module, plan)
                    except (OSError, RuntimeError, ValueError) as exc:
                        raise CheckpointRecoveryRefused(f"{label} private backup failed verification") from exc
                    proposed, encoded = build_closure(module, plan)
                    before_commit()
                    current = build_plan(module)
                    if not hmac.compare_digest(expected_token, current.report["review_token"]):
                        raise CheckpointRecoveryRefused(f"{label} inputs changed during backup/stopped check")
                    require_absence(current)
                    module._assert_journal_session(module._active_journal_session())
                    expected = current.inputs["adversary_combat_actions.jsonl"] + encoded
                    if _read_regular(module.receipt_path, 32 * 1024 * 1024) != current.inputs[
                            "adversary_combat_actions.jsonl"]:
                        raise CheckpointRecoveryRefused(f"{label} journal changed before closure append")
                    # Keep the checkpoint behind the *whole* closed batch. Any
                    # partial append or intermediate anchor/witness failure then
                    # remains an explicit startup hold, before host reconciliation.
                    try:
                        module._append_pinned_journal_bytes(encoded)
                    finally:
                        module._invalidate_journal_cache()
                    if _read_regular(module.receipt_path, 32 * 1024 * 1024) != expected:
                        raise CheckpointRecoveryRefused(f"{label} durable closure batch differs from its proof")
                    authenticated = _authenticated_host_records(module, expected)
                    validate_prefix(module, authenticated, set(), set())
                    if module._ordered_pending_phases(authenticated) or _pending_host_undos(authenticated):
                        raise CheckpointRecoveryRefused(f"{label} durable closure batch leaves pending work")
                    for record in (current.records[-1], *proposed[-2:]):
                        before_commit()
                        require_absence(current)
                        module._assert_journal_session(module._active_journal_session())
                        if _read_regular(module.receipt_path, 32 * 1024 * 1024) != expected:
                            raise CheckpointRecoveryRefused(f"{label} closure changed before checkpoint advance")
                        module._advance_recovery_anchor(record)
                    module._invalidate_journal_cache()
                    records, legacy = module._read_journal(strict=True)
                    validate_prefix(module, records, set(), set())
                    require_absence(current)
                    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
                    module._verify_recovery_witness(anchor)
                    witness = module._read_recovery_witness()
                    if (legacy or len(records) != len(plan.records) + 2
                            or _read_regular(module.receipt_path, 32 * 1024 * 1024) != expected
                            or module._pending_recovery_records() or _pending_host_undos(records)
                            or anchor["last_journal_sequence"] != len(records)
                            or witness["last_journal_sequence"] != len(records)
                            or anchor["last_journal_hmac"] != proposed[-1]["record_hmac"]
                            or _read_regular(module.data_root / "bus.key", 256) != plan.inputs["bus.key"]):
                        raise CheckpointRecoveryRefused(f"{label} final prefix/phase/authority verification failed")
                    return {**plan.report, "recovered": True, "journal_records": len(records),
                            "checkpoint_sequence": len(records), "pending_actions": 0, "pending_undos": 0,
                            "witness_sequence": witness["last_journal_sequence"],
                            "backup_directory": str(directory),
                            "closure": "rules already absent; no host removal or other host action performed"}



def recover_host_undo_checkpoint(module, *, expected_token: str,
                                 before_commit: Callable[[], None]) -> dict[str, Any]:
    """Explicit stopped host-only accounting closure; no host action or rearm."""
    return _recover_firewall_undo_checkpoint(module, expected_token=expected_token,
                                             before_commit=before_commit)


def recover_program_undo_checkpoint(module, *, expected_token: str,
                                    before_commit: Callable[[], None]) -> dict[str, Any]:
    """Explicit stopped program-only accounting closure; no host action or rearm."""
    return _recover_firewall_undo_checkpoint(module, expected_token=expected_token,
                                             before_commit=before_commit, program=True)
