"""Exact completed rollback accounting, with inert authority and firewall reads."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from angerona.core import combat_checkpoint_recovery as recovery, secure_store
from angerona.core.eventbus import Event, Severity
from angerona.modules.adversary_combat import JournalIntegrityError


def _fixture(tmp_path, monkeypatch):
    (tmp_path / "bus.key").write_text((b"r" * 32).hex(), encoding="ascii")
    protected = tmp_path / "secrets.dpapi"
    protected.write_bytes(b"inert protected store")
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
    event = Event("Purple Remediation Guard", "inert fixture", Severity.HIGH)
    startup = module._action("activate_honeypots", "Smart Deception", event, "startup",
                             reversible=True, details={"module": "Smart Deception"})
    module._journal_intent(startup)
    module._journal_failure(startup, "orphaned intent had no observed postcondition")
    exe = str(tmp_path / "owned-inert.exe")
    action = module._action("isolate_program", exe, event, "combat-123456789abc",
                            reversible=True, details={
                                "pid": 2468, "create_time": 1234.5, "exe": exe,
                                "rules": ["Angerona-Combat-Program-2468-0123abcd"],
                            })
    module._journal_intent(action)
    orphan = module._append_journal({
        **asdict(action), "record_type": "orphan", "status": "orphaned",
        "orphaned_at": 2000000001.0, "error": "program firewall postcondition failed",
        "rollback_state": "pending",
    })
    # Times are explicit and ordered; no firewall rule is ever created/deleted.
    for phase, status, stamp in (("undo_intent", "pending", 2000000002.0),
                                 ("undo_commit", "undone", 2000000003.0)):
        module._append_journal({
            "record_type": phase, "undo_id": "undo-0123456789abcdef",
            "undo_of": action.action_id, "action": "isolate_program",
            "phase_at": stamp, "status": status, "error": "", "recovery": True,
            "bound_record_hmac": orphan["record_hmac"],
        })
    with monkeypatch.context() as patch:
        patch.setattr(module, "_advance_recovery_anchor", lambda _r: (
            _ for _ in ()).throw(OSError("inert interrupted terminal checkpoint")))
        with pytest.raises(JournalIntegrityError):
            module._append_journal({
                "record_type": "failure", "action_id": action.action_id,
                "combat_id": action.combat_id, "action": action.action,
                "failed_at": 2000000004.0, "status": "failed",
                "error": "program firewall postcondition failed; uncertain mutation rolled back",
            })
    monkeypatch.setattr(recovery, "_native_firewall_rule_absent", lambda _rule: True)
    return module, values


def _authority(module):
    paths = (module.receipt_path, module.data_root / "secrets.dpapi",
             module.recovery_witness_path, module.data_root / "bus.key")
    return {path: path.read_bytes() for path in paths}


def _rewrite(module, mutate):
    """Create a signed but semantically invalid fixture, keeping its anchor."""
    records = [json.loads(line) for line in module.receipt_path.read_bytes().splitlines()]
    mutate(records)
    previous = "0" * 64
    for index, record in enumerate(records, 1):
        record.update(sequence=index, previous_hmac=previous)
        core = {key: value for key, value in record.items() if key != "record_hmac"}
        record["record_hmac"] = module._record_hmac(core)
        previous = record["record_hmac"]
    module.receipt_path.write_bytes(b"".join(
        module._canonical_record(record) + b"\n" for record in records
    ))


def _apply(module, token=None, guard=lambda: None):
    token = token or recovery.inspect_rollback_checkpoint(module)["review_token"]
    return recovery.recover_rollback_checkpoint(module, expected_token=token, before_commit=guard)


def test_previous_workflow_holds_and_new_recovery_preserves_signed_history(tmp_path, monkeypatch):
    module, values = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    with pytest.raises(JournalIntegrityError, match="incomplete anchor transaction"):
        module._read_journal(strict=True)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="recovery or undo"):
        recovery.inspect_drill_checkpoint(module)
    report = recovery.inspect_rollback_checkpoint(module)
    assert report["journal_records"] == 7 and report["checkpoint_sequence"] == 6
    assert _authority(module) == before
    calls = []
    result = _apply(module, report["review_token"], guard=lambda: calls.append("stopped"))
    assert calls == ["stopped", "stopped"]
    assert result["recovered"] and result["checkpoint_sequence"] == 7
    assert result["host_actions_executed"] == 0 and result["rearmed"] is False
    assert module.receipt_path.read_bytes() == before[module.receipt_path]
    assert (tmp_path / "bus.key").read_bytes() == before[tmp_path / "bus.key"]
    assert values["UNRELATED_SECRET"] == "preserve"
    backup = Path(result["backup_directory"])
    for path, raw in before.items():
        if path.name == "bus.key":
            assert not (backup / path.name).exists()
        else:
            assert (backup / path.name).read_bytes() == raw
    records, legacy = module._read_journal(strict=True)
    assert not legacy and len(records) == 7
    assert module._pending_recovery_records() == {}
    assert module._response_initialized is False
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="one-terminal"):
        recovery.inspect_rollback_checkpoint(module)


@pytest.mark.parametrize("absent", [False, None, 0, 1, "absent"])
def test_presence_unknown_and_nonboolean_observation_never_advance(tmp_path, monkeypatch, absent):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_rollback_checkpoint(module)["review_token"]
    monkeypatch.setattr(recovery, "_native_firewall_rule_absent", lambda _rule: absent)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="absence"):
        _apply(module, token)
    assert _authority(module) == before
    assert not list(tmp_path.glob("combat-rollback-recovery-*"))


@pytest.mark.parametrize("mutation", [
    lambda r: r[-1].update(action_id="act-ffffffffffffffff"),
    lambda r: r[-1].update(combat_id="combat-ffffffffffff"),
    lambda r: r[-1].update(status="applied"),
    lambda r: r[-1].update(error="different reason"),
    lambda r: r[-2].update(status="undo_failed"),
    lambda r: r[-2].update(record_type="undo_failure"),
    lambda r: r[-2].update(undo_id="undo-ffffffffffffffff"),
    lambda r: r[-2].update(bound_record_hmac="0" * 64),
    lambda r: r[-2].update(recovery=False),
    lambda r: r[-2].update(error="unavailable"),
    lambda r: r[-3].update(undo_of="act-ffffffffffffffff"),
    lambda r: r[-3].update(phase_at=2000000005.0),
    lambda r: r[-4].update(rollback_state="unknown"),
    lambda r: r[-4].update(mutation_started=True),
    lambda r: r[-4].update(error="different reason"),
    lambda r: r[-5].update(reversible=False),
    lambda r: r[-5]["details"].update(pid=True),
    lambda r: r[-5]["details"].update(create_time=True),
    lambda r: r[-5]["details"].update(rules=["unrelated"]),
    lambda r: r[-5]["details"].update(exe="relative.exe"),
    lambda r: r[0].update(action="terminate_process"),
    lambda r: r[1].update(action_id="act-ffffffffffffffff"),
    lambda r: r.insert(2, dict(r[0])),
])
def test_signed_but_wrong_phase_or_target_contract_is_refused(tmp_path, monkeypatch, mutation):
    module, _ = _fixture(tmp_path, monkeypatch)
    _rewrite(module, mutation)
    before = _authority(module)
    with pytest.raises((recovery.CheckpointRecoveryRefused, JournalIntegrityError)):
        recovery.inspect_rollback_checkpoint(module)
    assert _authority(module) == before


@pytest.mark.parametrize("malformed", ["action-type", "commit-details"])
def test_malformed_signed_history_has_a_typed_refusal(tmp_path, monkeypatch, malformed):
    module, _ = _fixture(tmp_path, monkeypatch)

    def change(records):
        if malformed == "action-type":
            records[0]["action"] = {}
        else:
            records[1] = {**records[0], "record_type": "commit", "status": "applied",
                          "committed_at": records[0]["intent_at"], "details": None}
            records[1].pop("intent_at")

    _rewrite(module, change)
    before = _authority(module)
    with pytest.raises(recovery.CheckpointRecoveryRefused, match="intent|commit binding"):
        recovery.inspect_rollback_checkpoint(module)
    assert _authority(module) == before


@pytest.mark.parametrize("changed", ["journal", "partial", "witness", "key", "protected", "hardlink"])
def test_changed_or_unsafe_authority_stays_held(tmp_path, monkeypatch, changed):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_rollback_checkpoint(module)["review_token"]
    if changed == "journal":
        module.receipt_path.write_bytes(module.receipt_path.read_bytes().replace(b"isolate_program", b"isolate_progrxm"))
    elif changed == "partial":
        module.receipt_path.write_bytes(module.receipt_path.read_bytes().rstrip(b"\n"))
    elif changed == "witness":
        module.recovery_witness_path.write_bytes(b"{}")
    elif changed == "key":
        (tmp_path / "bus.key").write_text((b"x" * 32).hex(), encoding="ascii")
    elif changed == "protected":
        (tmp_path / "secrets.dpapi").write_bytes(b"changed protected store")
    else:
        __import__("os").link(module.receipt_path, tmp_path / "alias.jsonl")
    before = _authority(module)
    with pytest.raises((JournalIntegrityError, ValueError, OSError)):
        _apply(module, token)
    assert _authority(module) == before


@pytest.mark.parametrize("stage", ["backup", "protected_changed", "rule_appeared", "guard", "journal_changed"])
def test_changed_apply_boundary_never_advances_authority(tmp_path, monkeypatch, stage):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_rollback_checkpoint(module)["review_token"]
    original_backup = recovery._backup_rollback
    expected = _authority(module)

    def backup(current, plan):
        if stage == "backup":
            raise OSError("inert backup failure")
        directory = original_backup(current, plan)
        if stage == "protected_changed":
            (tmp_path / "secrets.dpapi").write_bytes(b"concurrent protected generation")
        elif stage == "journal_changed":
            current.receipt_path.write_bytes(current.receipt_path.read_bytes() + b" ")
        elif stage == "rule_appeared":
            monkeypatch.setattr(recovery, "_native_firewall_rule_absent", lambda _: False)
        expected.update(_authority(current))
        return directory

    calls = []

    def guard():
        calls.append(True)
        if stage == "guard" and len(calls) == 2:
            raise ValueError("application restarted")

    monkeypatch.setattr(recovery, "_backup_rollback", backup)
    with pytest.raises((JournalIntegrityError, ValueError, OSError)):
        _apply(module, token, guard)
    assert _authority(module) == expected


def test_token_and_stopped_guard_are_required_before_writes(tmp_path, monkeypatch):
    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    for token, guard in (("", lambda: None), ("0" * 64, None), ("0" * 64, lambda: None)):
        with pytest.raises(recovery.CheckpointRecoveryRefused):
            recovery.recover_rollback_checkpoint(module, expected_token=token, before_commit=guard)
        assert _authority(module) == before
    assert not list(tmp_path.glob("combat-rollback-recovery-*"))


def test_witness_failure_after_anchor_advance_stays_held_and_keeps_backups(tmp_path, monkeypatch):
    module, _ = _fixture(tmp_path, monkeypatch)
    token = recovery.inspect_rollback_checkpoint(module)["review_token"]
    before = _authority(module)
    monkeypatch.setattr(module, "_write_recovery_witness", lambda _anchor: (
        _ for _ in ()).throw(OSError("inert witness write failure")))
    with pytest.raises(JournalIntegrityError, match="custody is unavailable") as refused:
        _apply(module, token)
    assert isinstance(refused.value.__cause__, OSError)
    assert "witness write failure" in str(refused.value.__cause__)
    # The completed anchor write is evidence, not something to silently undo.
    # No success/rearm is returned when the next authority write fails.
    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
    witness = module._read_recovery_witness()
    assert anchor["last_journal_sequence"] == 7
    assert witness["last_journal_sequence"] == 6
    assert module._response_initialized is False
    assert module.receipt_path.read_bytes() == before[module.receipt_path]
    assert module.recovery_witness_path.read_bytes() == before[module.recovery_witness_path]
    assert (tmp_path / "bus.key").read_bytes() == before[tmp_path / "bus.key"]
    backups = list(tmp_path.glob("combat-rollback-recovery-*"))
    assert len(backups) == 1
    for path, raw in before.items():
        if path.name != "bus.key":
            assert (backups[0] / path.name).read_bytes() == raw
    with pytest.raises(JournalIntegrityError, match="signing-key witness"):
        module._read_journal(strict=True)
    with pytest.raises(JournalIntegrityError, match="signing-key witness"):
        recovery.inspect_rollback_checkpoint(module)


def test_cli_defaults_to_inspection_and_blocks_running_apply(tmp_path, monkeypatch, capsys):
    from tools import recover_combat_rollback as cli

    module, _ = _fixture(tmp_path, monkeypatch)
    before = _authority(module)
    monkeypatch.setattr(cli, "existing_installation", lambda _: module)
    monkeypatch.setattr("sys.argv", ["recover", "--data-root", str(tmp_path)])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["eligible"] is True
    assert _authority(module) == before
    monkeypatch.setattr("sys.argv", ["recover", "--data-root", str(tmp_path), "--apply",
                                    "--expected-token", "0" * 64])
    monkeypatch.setattr(cli, "_require_stopped", lambda: (_ for _ in ()).throw(ValueError("Stop Angerona")))
    assert cli.main() == 1
    assert "Stop Angerona" in json.loads(capsys.readouterr().out)["error"]
    assert _authority(module) == before


@pytest.mark.parametrize("result,expected", [
    ("present", False), (0x80070002, True), (0x80070005, None),
    ((0x80020009, 0x80070002), True), ((0x80020009, 0x80070005), None),
    (0x80070057, None), ("unavailable", None),
])
def test_native_query_only_admits_documented_missing_rule_hresult(monkeypatch, result, expected):
    import sys
    from types import SimpleNamespace

    calls = []

    class ComError(Exception):
        def __init__(self, code, inner=None):
            self.hresult = code
            self.excepinfo = (0, None, None, None, 0, inner) if inner else None

    class Rules:
        def Item(self, rule):
            calls.append(("query", rule))
            if result == "unavailable":
                raise OSError("inert RPC failure")
            if isinstance(result, tuple):
                raise ComError(*result)
            if type(result) is int:
                raise ComError(result)
            return object()

    native = object()
    pythoncom = SimpleNamespace(
        COINIT_APARTMENTTHREADED=2, CLSCTX_INPROC_SERVER=1, IID_IDispatch="dispatch",
        CoInitializeEx=lambda mode: calls.append(("init", mode)),
        MakeIID=lambda value: value,
        CoCreateInstance=lambda *args: native,
        CoUninitialize=lambda: calls.append(("retired",)),
    )
    monkeypatch.setattr(recovery, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "pythoncom", pythoncom)
    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(com_error=ComError))
    monkeypatch.setitem(sys.modules, "win32com.client", SimpleNamespace(
        dynamic=SimpleNamespace(Dispatch=lambda value: SimpleNamespace(Rules=Rules())),
    ))
    rule = "Angerona-Combat-Program-2468-0123abcd"
    assert recovery._native_firewall_rule_absent(rule) is expected
    assert calls == [("init", 2), ("query", rule), ("retired",)]
