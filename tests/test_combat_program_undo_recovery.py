"""Program-only stopped accounting with real HMACs and inert host providers."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import time

import pytest

from angerona.core import combat_checkpoint_recovery as recovery, secure_store
from angerona.core.eventbus import Event, Severity
from angerona.modules.adversary_combat import JournalIntegrityError


def _fixture(tmp_path, monkeypatch):
    (tmp_path / "bus.key").write_text((b"p" * 32).hex(), encoding="ascii")
    protected = tmp_path / "secrets.dpapi"
    protected.write_bytes(b"inert existing protected store")
    values = {"UNRELATED_SECRET": "preserve"}
    monkeypatch.setattr(secure_store, "read_secret_values", lambda names, *_a, **_k: {
        name: values[name] for name in names if name in values
    })

    def write(updates, _root):
        values.update(updates)
        protected.write_text(json.dumps(values), encoding="utf-8")
        return protected

    monkeypatch.setattr(secure_store, "write_secret_map", write)
    module = recovery.existing_installation(tmp_path)
    module._read_journal(strict=True)
    event = Event("Inert detector", "fixture", Severity.HIGH)
    startup = module._action("activate_honeypots", "Smart Deception", event, "startup",
                             reversible=True, details={"module": "Smart Deception"})
    module._journal_intent(startup)
    module._journal_failure(startup, "orphaned intent had no observed postcondition")

    def rollback(kind, number, *, incomplete=False):
        exe = str(tmp_path / "inert-program.exe")
        details = ({"pid": 2468, "create_time": 1234.5, "exe": exe,
                    "rules": [f"Angerona-Combat-Program-2468-{number:08x}"]}
                   if kind == "isolate_program" else {
                       "rules": [f"Angerona-Combat-Host-{number:010x}-out",
                                 f"Angerona-Combat-Host-{number:010x}-in"]})
        action = module._action(kind, exe if kind == "isolate_program" else "all remote network traffic",
                                event, f"combat-{number:012x}", reversible=True, details=details)
        module._journal_intent(action)
        error = "program firewall postcondition failed" if kind == "isolate_program" else recovery._HOST_INCOMPLETE
        orphan = module._append_journal({**asdict(action), "record_type": "orphan",
            "status": "orphaned", "orphaned_at": time.time(), "error": error, "rollback_state": "pending"})
        undo = {"record_type": "undo_intent", "undo_id": f"undo-{number:016x}",
                "undo_of": action.action_id, "action": kind, "phase_at": time.time(),
                "status": "pending", "error": "", "recovery": True,
                "bound_record_hmac": orphan["record_hmac"]}
        if incomplete:
            with monkeypatch.context() as patch:
                patch.setattr(module, "_advance_recovery_anchor", lambda _: (
                    _ for _ in ()).throw(OSError("inert interrupted program checkpoint")))
                with pytest.raises(JournalIntegrityError):
                    module._append_journal(undo)
            return
        module._append_journal(undo)
        module._append_journal({**undo, "record_type": "undo_commit", "status": "undone", "phase_at": time.time()})
        module._journal_failure(action, recovery._HOST_NO_EFFECT if kind == "isolate_host"
                                else recovery._PROGRAM_NO_EFFECT)

    rollback("isolate_host", 1)
    rollback("isolate_program", 2)
    for index in range(3):
        pid, ticks = 10000 + index, 134000000000000000 + index * 10000000
        birth = (ticks - 116444736000000000) / 10000000
        exe = rf"C:\inert\worker{index}.exe"
        action = module._action("terminate_process", f"worker{index}.exe ({pid})", event,
            f"combat-{index+10:012x}", reversible=False, details={"pid": pid, "create_time": birth,
            "name": f"worker{index}.exe", "exe": exe, "process_custody": "windows-retained-handle-v1",
            "native_pid": pid, "native_birth_ticks": ticks, "native_image": exe.lower()})
        module._journal_intent(action)
        with module._terminal_commit_validator(lambda: {"native_image_observation": "before-termination",
                "native_exit_code": 1, "native_wait_signaled": True}):
            module._journal_commit(action)
    rollback("isolate_program", 3, incomplete=True)
    monkeypatch.setattr(recovery, "_native_firewall_rule_absent", lambda _: True)
    for method in ("_undo_record", "_run_firewall", "_reconcile_state"):
        monkeypatch.setattr(module, method, lambda *_a, **_k: pytest.fail("Recovery invoked a host action/rearm"))
    return module, values


def _authority(module):
    return {path: path.read_bytes() for path in (
        module.receipt_path, module.data_root / "secrets.dpapi", module.recovery_witness_path,
        module.data_root / "bus.key")}


def _apply(module, token=None, guard=lambda: None):
    token = token or recovery.inspect_program_undo_checkpoint(module)["review_token"]
    return recovery.recover_program_undo_checkpoint(module, expected_token=token, before_commit=guard)


def _rewrite(module, mutate):
    records = [json.loads(line) for line in module.receipt_path.read_bytes().splitlines()]
    mutate(records)
    previous, rebound = "0" * 64, {}
    for sequence, record in enumerate(records, 1):
        old = record["record_hmac"]
        if record.get("bound_record_hmac") in rebound:
            record["bound_record_hmac"] = rebound[record["bound_record_hmac"]]
        record.update(sequence=sequence, previous_hmac=previous)
        record["record_hmac"] = module._record_hmac({k: v for k, v in record.items() if k != "record_hmac"})
        previous = rebound[old] = record["record_hmac"]
    module.receipt_path.write_bytes(b"".join(module._canonical_record(r)+b"\n" for r in records))


def test_exact_program_closure_keeps_originals_termination_history_backups_and_hold(tmp_path, monkeypatch):
    module, values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    for inspect in (recovery.inspect_host_undo_checkpoint, recovery.inspect_rollback_checkpoint):
        with pytest.raises(JournalIntegrityError):
            inspect(module)
    report = recovery.inspect_program_undo_checkpoint(module)
    assert report["journal_records"] == 21 and report["checkpoint_sequence"] == 20
    assert len(report["rules"]) == 1 and _authority(module) == before
    guards = []
    result = _apply(module, report["review_token"], lambda: guards.append(True))
    assert len(guards) == 5
    assert result["recovered"] and result["checkpoint_sequence"] == result["witness_sequence"] == 23
    assert result["pending_actions"] == result["pending_undos"] == result["host_actions_executed"] == 0
    assert result["rearmed"] is False and module._response_initialized is False
    raw = module.receipt_path.read_bytes()
    assert raw.startswith(before[module.receipt_path])
    records, legacy = module._read_journal(strict=True)
    assert not legacy and module._pending_recovery_records() == {}
    assert records[-1]["error"] == recovery._PROGRAM_NO_EFFECT
    assert records[-2]["undo_id"] == records[-3]["undo_id"]
    assert values["UNRELATED_SECRET"] == "preserve"
    assert (tmp_path / "bus.key").read_bytes() == before[tmp_path / "bus.key"]
    backup = Path(result["backup_directory"])
    assert backup.name.startswith("combat-program-undo-recovery-")
    for path, original in before.items():
        assert not (backup/path.name).exists() if path.name == "bus.key" else (backup/path.name).read_bytes() == original
    fresh = recovery.existing_installation(tmp_path)
    for method in ("_intent_effect_present", "_undo_record", "_run_firewall", "_firewall_rule_exists"):
        monkeypatch.setattr(fresh, method, lambda *_a, **_k: pytest.fail("Completed closure dispatched host work"))
    assert fresh._reconcile_state() is True and fresh._response_initialized is False


def _change_native(key, value):
    def change(records):
        index = next(i for i, r in enumerate(records) if r.get("action") == "terminate_process")
        for record in records[index:index+2]:
            record["details"][key] = value
    return change


def _duplicate_native_generation(records):
    action, combat = records[14]["action_id"], records[14]["combat_id"]
    for offset in (0, 1):
        duplicate = json.loads(json.dumps(records[12+offset]))
        duplicate.update(action_id=action, combat_id=combat)
        records[14+offset] = duplicate


@pytest.mark.parametrize("mutation", [
    _change_native("native_pid", True), _change_native("native_pid", 999),
    _change_native("native_birth_ticks", True), _change_native("native_birth_ticks", 1),
    _change_native("native_image", r"C:\inert\different.exe"),
    _change_native("process_custody", "pid-only"), _change_native("mutation_generation", ""),
    _change_native("create_time", True), _change_native("create_time", 1e99),
    lambda r: r[13]["details"].update(native_wait_signaled=1),
    lambda r: r[13]["details"].update(postcondition_verified=False),
    lambda r: r[13]["details"].update(native_exit_code=True),
    lambda r: r[13]["details"].update(native_image_observation="after-termination"),
    lambda r: r[13]["details"].update(unfamiliar_terminal_proof=True),
    lambda r: r[13]["details"].update(native_pid=float(r[12]["details"]["pid"])),
    lambda r: r[13].update(reversible=0),
    lambda r: r[13].update(target="different process"),
    lambda r: r[13].update(action_id="act-ffffffffffffffff"),
    lambda r: r[13].update(record_type="failure", status="failed"),
    lambda r: r.pop(13), _duplicate_native_generation,
    lambda r: r[-1].update(bound_record_hmac="0"*64),
    lambda r: r[-1].update(recovery=False), lambda r: r[-1].update(undo_of="act-ffffffffffffffff"),
    lambda r: r[-2].update(error="unfamiliar failure"),
    lambda r: r[-3]["details"].update(rules=["unmanaged-rule"]),
    lambda r: r[-3].update(reversible=False),
])
def test_authenticated_but_ambiguous_history_or_tail_never_authorizes_recovery(tmp_path, monkeypatch, mutation):
    module, _ = _fixture(tmp_path, monkeypatch)
    _rewrite(module, mutation)
    before = _authority(module)
    with pytest.raises(JournalIntegrityError):
        recovery._program_undo_records(module, before[module.receipt_path])
    with pytest.raises(JournalIntegrityError):
        recovery.inspect_program_undo_checkpoint(module)
    assert _authority(module) == before


@pytest.mark.parametrize("state", [False, None, 1, "absent"])
def test_native_absence_must_be_exact_true_before_any_write(tmp_path, monkeypatch, state):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_program_undo_checkpoint(module)["review_token"]
    before = _authority(module)
    monkeypatch.setattr(recovery, "_native_firewall_rule_absent", lambda _: state)
    with pytest.raises(JournalIntegrityError, match="natively absent"):
        _apply(module, token)
    assert _authority(module) == before


@pytest.mark.parametrize("stage", ["partial", "partial-failure", "batch", "anchor-witness", "checkpoint452", "undo-witness", "checkpoint453", "last-witness"])
def test_every_incomplete_boundary_holds_a_fresh_startup_without_host_work(tmp_path, monkeypatch, stage):
    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    token = recovery.inspect_program_undo_checkpoint(module)["review_token"]
    original_append, original_advance = module._append_pinned_journal_bytes, module._advance_recovery_anchor
    original_witness = module._write_recovery_witness
    advances, witnesses = [], []

    def append(payload):
        lines = payload.splitlines(keepends=True)
        partial = (payload[:len(payload)//3] if stage == "partial" else
                   lines[0] + lines[1][:len(lines[1])//2] if stage == "partial-failure" else payload)
        original_append(partial)
        if stage in {"partial", "partial-failure", "batch"}:
            raise OSError("inert append interruption")

    def witness(anchor):
        witnesses.append(True)
        if ((stage == "anchor-witness" and len(witnesses) == 1)
                or (stage == "undo-witness" and len(witnesses) == 2)
                or (stage == "last-witness" and len(witnesses) == 3)):
            raise OSError("inert witness interruption")
        return original_witness(anchor)

    def advance(record):
        advances.append(True)
        original_advance(record)
        if (stage == "checkpoint452" and len(advances) == 1) or (stage == "checkpoint453" and len(advances) == 2):
            raise OSError("inert checkpoint interruption")

    monkeypatch.setattr(module, "_append_pinned_journal_bytes", append)
    monkeypatch.setattr(module, "_advance_recovery_anchor", advance)
    monkeypatch.setattr(module, "_write_recovery_witness", witness)
    with pytest.raises((JournalIntegrityError, OSError)):
        _apply(module, token)
    assert module.receipt_path.read_bytes().startswith(before[module.receipt_path])
    assert (tmp_path / "bus.key").read_bytes() == before[tmp_path / "bus.key"]
    fresh = recovery.existing_installation(tmp_path)
    for method in ("_intent_effect_present", "_undo_record", "_run_firewall"):
        monkeypatch.setattr(fresh, method, lambda *_a, **_k: pytest.fail("Interrupted closure dispatched host work"))
    assert fresh._reconcile_state() is False and fresh._mutation_blocked
    with pytest.raises(JournalIntegrityError):
        recovery.inspect_program_undo_checkpoint(fresh)
    backups = list(tmp_path.glob("combat-program-undo-recovery-*"))
    assert len(backups) == 1
    for path, original in before.items():
        if path.name != "bus.key":
            assert (backups[0]/path.name).read_bytes() == original


@pytest.mark.parametrize("boundary", ["stale-token", "stopped", "backup", "key", "journal", "witness", "protected"])
def test_program_compare_and_swap_and_prewrite_failures_never_append(tmp_path, monkeypatch, boundary):
    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    token = recovery.inspect_program_undo_checkpoint(module)["review_token"]
    guard = lambda: None
    if boundary == "stale-token":
        token = "0"*64
    elif boundary == "stopped":
        guard = lambda: (_ for _ in ()).throw(ValueError("inert suite still running"))
    else:
        original = recovery._backup_program_undo

        def backup(current, plan):
            if boundary == "backup":
                raise OSError("inert backup failure")
            directory = original(current, plan)
            path = {"key": tmp_path/"bus.key", "journal": module.receipt_path,
                    "witness": module.recovery_witness_path, "protected": tmp_path/"secrets.dpapi"}[boundary]
            path.write_bytes((b"a"*64) if boundary == "key" else before[path] + b" ")
            return directory

        monkeypatch.setattr(recovery, "_backup_program_undo", backup)
    with pytest.raises((JournalIntegrityError, ValueError)):
        _apply(module, token, guard)
    if boundary in {"stale-token", "stopped", "backup"}:
        assert _authority(module) == before
    else:
        for path, original in before.items():
            if ((boundary == "key" and path.name == "bus.key")
                    or (boundary == "journal" and path == module.receipt_path)
                    or (boundary == "witness" and path == module.recovery_witness_path)
                    or (boundary == "protected" and path.name == "secrets.dpapi")):
                assert path.read_bytes() == ((b"a"*64) if boundary == "key" else original+b" ")
            else:
                assert path.read_bytes() == original


def test_cli_read_only_default_and_shared_stopped_guard_blocks_blackbox(tmp_path, monkeypatch, capsys):
    import psutil
    from types import SimpleNamespace
    from tools import recover_combat_program_undo as cli, recover_combat_host_undo as host_cli

    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    monkeypatch.setattr(cli, "existing_installation", lambda _: module)
    monkeypatch.setattr(host_cli, "_require_core_stopped", lambda: None)
    monkeypatch.setattr(psutil, "process_iter", lambda _: [])
    monkeypatch.setattr("sys.argv", ["recover", "--data-root", str(tmp_path)])
    assert cli.main() == 0 and json.loads(capsys.readouterr().out)["eligible"]
    assert _authority(module) == before
    process = SimpleNamespace(pid=123, info={"name":"python.exe"},
        cmdline=lambda: ["python.exe", r"C:\source\blackbox_recorder.py"])
    monkeypatch.setattr(psutil, "process_iter", lambda _: [process])
    monkeypatch.setattr("sys.argv", ["recover", "--data-root", str(tmp_path), "--apply", "--expected-token", "0"*64])
    assert cli.main() == 1 and "Stop Black Box" in json.loads(capsys.readouterr().out)["error"]
    assert _authority(module) == before
