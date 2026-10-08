"""Recover only a proven unapplied, suite-owned inert drill checkpoint.

This is not a general journal repair facility. No target is moved, removed or
executed; no signing authority is created; no historical journal byte changes.
The ordinary Combat reconciliation subsequently records the unapplied intent.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Callable

from angerona.modules.adversary_combat import JournalIntegrityError


class CheckpointRecoveryRefused(JournalIntegrityError):
    """The exact no-effect drill recovery contract could not be proved."""


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
