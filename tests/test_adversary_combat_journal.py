from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import angerona.modules.adversary_combat as combat_module
import pytest
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules.adversary_combat import AdversaryCombat


def _combat(tmp_path, **overrides) -> AdversaryCombat:
    values = {
        "data_dir": tmp_path,
        "adversary_combat_enabled": True,
        "adversary_combat_mode": "maximum",
        "adversary_combat_min_severity": "LOW",
        "adversary_combat_block_network": False,
        "adversary_combat_quarantine_files": True,
        "adversary_combat_process_action": "terminate",
        "adversary_combat_isolate_host": False,
        "adversary_combat_activate_honeypots": False,
        "adversary_combat_isolation_threshold": 3,
    }
    values.update(overrides)
    manager = SimpleNamespace(config=SimpleNamespace(**values), modules={})
    module = AdversaryCombat(tmp_path)
    module.bind(EventBus())
    module.bind_manager(manager)
    manager.modules[module.name] = module
    return module


def _event(**details) -> Event:
    details.setdefault("active_attack", True)
    details.setdefault("response_authorized", True)
    actions: list[str] = []
    targets: dict[str, object] = {}
    if details.get("path"):
        actions.append("quarantine_file")
        targets["path"] = details["path"]
    if details.get("remote_ip"):
        actions.append("block_remote_ip")
        targets["remote_ips"] = [details["remote_ip"]]
    if not actions:
        actions.append("isolate_host")
        targets["host"] = "local"
    details.setdefault(
        "response_contract",
        {"version": 1, "actions": actions, "targets": targets},
    )
    return Event("EDR", "verified detector contract", Severity.HIGH, time.time(), details)


def _quarantine(module: AdversaryCombat, path) -> dict:
    module._handle(_event(path=str(path)))
    return next(
        item for item in module.list_actions() if item["action"] == "quarantine_file"
    )


def test_generic_high_event_is_default_deny_without_response_contract(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    mutations: list[str] = []
    monkeypatch.setattr(
        module, "_isolate_host", lambda *_args: mutations.append("isolate") or None
    )

    module._handle(Event(
        "EDR",
        "generic high",
        Severity.CRITICAL,
        time.time(),
        {"response_authorized": True},
    ))

    assert mutations == []
    assert list(module._active_events) == []
    assert module.list_actions() == []


def test_mismatched_target_contract_fails_closed(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    mutations: list[str] = []
    monkeypatch.setattr(
        module, "_quarantine_file", lambda *_args: mutations.append("file") or None
    )
    event = _event(path=str(artifact))
    event.details["response_contract"]["targets"]["path"] = str(tmp_path / "other.bin")

    module._handle(event)

    assert mutations == []
    assert artifact.read_bytes() == b"hostile"


def test_contract_allows_only_named_mutation(tmp_path, monkeypatch):
    module = _combat(tmp_path, adversary_combat_isolate_host=True)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    isolated: list[bool] = []
    monkeypatch.setattr(
        module, "_isolate_host", lambda *_args: isolated.append(True) or None
    )
    event = _event(path=str(artifact))
    event = Event(event.module, event.message, Severity.CRITICAL, event.ts, event.details)

    module._handle(event)

    assert not artifact.exists()
    assert isolated == []


def test_process_contract_requires_exact_pid_and_create_time(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    acted: list[bool] = []
    monkeypatch.setattr(
        module, "_act_on_process", lambda *_args, **_kwargs: acted.append(True) or []
    )
    details = {
        "active_attack": True,
        "response_authorized": True,
        "pid": 4242,
        "process_create_time": 10.0,
        "response_contract": {
            "version": 1,
            "actions": ["terminate_process"],
            "targets": {"pid": 4242, "process_create_time": 11.0},
        },
    }

    module._handle(Event("EDR", "process", Severity.CRITICAL, time.time(), details))

    assert acted == []


def test_journal_is_hmac_authenticated_and_hash_chained(tmp_path):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")

    action = _quarantine(module, artifact)
    records = [
        json.loads(line) for line in module.receipt_path.read_text(encoding="utf-8").splitlines()
    ]

    assert [record["record_type"] for record in records] == ["intent", "commit"]
    assert records[0]["previous_hmac"] == "0" * 64
    assert records[1]["previous_hmac"] == records[0]["record_hmac"]
    assert records[0]["sequence"] == 1 and records[1]["sequence"] == 2
    assert all(len(record["record_hmac"]) == 64 for record in records)
    assert action["integrity_status"] == "verified"


def test_intent_fsync_precedes_quarantine_mutation(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    observed: list[bool] = []
    real_move = combat_module._PinnedFileMove.rename_to

    def move(pinned, destination):
        records, _legacy = module._read_journal(strict=True)
        observed.append(records[-1]["record_type"] == "intent")
        return real_move(pinned, destination)

    monkeypatch.setattr(combat_module._PinnedFileMove, "rename_to", move)

    _quarantine(module, artifact)

    assert observed == [True]


def test_failed_intent_write_causes_no_mutation(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")

    monkeypatch.setattr(
        module,
        "_append_journal",
        lambda _payload: (_ for _ in ()).throw(OSError("disk unavailable")),
    )

    module._handle(_event(path=str(artifact)))

    assert artifact.read_bytes() == b"hostile"
    assert not module.quarantine_root.exists()


def test_mutation_failure_appends_authenticated_failure(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    monkeypatch.setattr(
        combat_module._PinnedFileMove,
        "rename_to",
        lambda *_args: (_ for _ in ()).throw(OSError("move failed")),
    )

    module._handle(_event(path=str(artifact)))
    records, _legacy = module._read_journal(strict=True)

    assert artifact.exists()
    assert [record["record_type"] for record in records] == ["intent", "failure"]


def test_forced_source_swap_cannot_quarantine_attacker_selected_file(
    tmp_path, monkeypatch
):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"receipt-bound hostile")
    attacker = tmp_path / "attacker-selected.bin"
    attacker.write_bytes(b"must not be quarantined")
    parked = tmp_path / "hostile-parked.bin"
    real_move = combat_module._PinnedFileMove.rename_to

    def force_swap(pinned, destination):
        try:
            pinned.path.replace(parked)
            attacker.replace(pinned.path)
        except OSError as exc:
            # Windows handle sharing prevents the swap before the exact-file
            # rename. Abort this attempt so the test also covers fail-closed.
            raise OSError("forced swap blocked") from exc
        return real_move(pinned, destination)

    monkeypatch.setattr(combat_module._PinnedFileMove, "rename_to", force_swap)
    module._handle(_event(path=str(artifact)))

    assert not any(
        item["action"] == "quarantine_file" for item in module.list_actions()
    )
    assert not any(
        path.read_bytes() == b"must not be quarantined"
        for path in module.quarantine_root.rglob("*")
        if path.is_file()
    )


def test_forced_quarantine_swap_cannot_plant_file_at_original_target(
    tmp_path, monkeypatch
):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"receipt-bound hostile")
    action = _quarantine(module, artifact)
    quarantine = Path(action["details"]["quarantine"])
    attacker = tmp_path / "attacker-selected.bin"
    attacker.write_bytes(b"must not be restored")
    parked = quarantine.with_name("receipt-file-parked.bin")
    real_move = combat_module._PinnedFileMove.rename_to

    def force_swap(pinned, destination):
        try:
            pinned.path.replace(parked)
            attacker.replace(pinned.path)
        except OSError as exc:
            raise OSError("forced swap blocked") from exc
        return real_move(pinned, destination)

    monkeypatch.setattr(combat_module._PinnedFileMove, "rename_to", force_swap)
    result = module.undo_action(action["action_id"])

    assert result["ok"] is False
    assert not artifact.exists()


def test_commit_write_failure_is_immediately_rolled_back_and_recorded(
    tmp_path, monkeypatch
):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    original_append = module._append_journal

    def fail_commit(payload):
        if payload.get("record_type") == "commit":
            raise OSError("crash before commit")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", fail_commit)
    module._handle(_event(path=str(artifact)))
    assert artifact.read_bytes() == b"hostile"

    records, _legacy = module._read_journal(strict=True)
    assert [record["record_type"] for record in records] == [
        "intent", "orphan", "undo_intent", "undo_commit", "failure"
    ]

    restarted = _combat(tmp_path)
    restarted._reconcile_state()

    assert artifact.read_bytes() == b"hostile"
    assert restarted.list_actions() == []


def test_failed_immediate_orphan_rollback_is_retried_on_restart(
    tmp_path, monkeypatch
):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    original_append = module._append_journal

    def fail_commit(payload):
        if payload.get("record_type") == "commit":
            raise OSError("commit unavailable")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", fail_commit)
    monkeypatch.setattr(module, "_undo_record", lambda _record: (False, "busy"))
    module._handle(_event(path=str(artifact)))
    assert not artifact.exists()
    assert module._mutation_blocked is True
    assert module.response_ready() is False
    visible = module.list_actions()
    assert len(visible) == 1
    assert visible[0]["status"] == "recovery_required"
    assert visible[0]["integrity_status"] == "verified"
    records, _legacy = module._read_journal(strict=True)
    assert records[-1]["record_type"] == "orphan"
    assert records[-1]["rollback_state"] == "retry_on_startup"

    restarted = _combat(tmp_path)
    assert restarted._reconcile_state() is True
    assert artifact.read_bytes() == b"hostile"


def test_recovery_required_orphan_is_undoable_and_circuit_rearms(
    tmp_path, monkeypatch
):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    original_append = module._append_journal
    original_undo = module._undo_record

    def fail_commit(payload):
        if payload.get("record_type") == "commit":
            raise OSError("commit unavailable")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", fail_commit)
    monkeypatch.setattr(module, "_undo_record", lambda _record: (False, "busy"))
    module._handle(_event(path=str(artifact)))
    recovery = module.list_actions()[0]

    # The circuit rejects every later mutation while the exact orphan remains.
    later = tmp_path / "later.bin"
    later.write_bytes(b"later")
    module._handle(_event(path=str(later)))
    assert later.exists()

    monkeypatch.setattr(module, "_append_journal", original_append)
    monkeypatch.setattr(module, "_undo_record", original_undo)
    result = module.undo_action(recovery["action_id"])

    assert result["ok"] is True
    assert artifact.read_bytes() == b"hostile"
    assert module._mutation_blocked is False
    assert not any(
        record.get("recovery_required") for record in module.list_actions()
    )


def test_nonreversible_commit_failure_opens_circuit_and_is_visible(
    tmp_path, monkeypatch
):
    module = _combat(tmp_path)
    action = combat_module.CombatAction(
        action_id="act-1111111111111111",
        combat_id="combat-aaaaaaaaaaaa",
        action="terminate_process",
        applied_at=time.time(),
        reversible=False,
        target="4242",
        details={"pid": 4242, "create_time": 1234.5},
        trigger_module="test",
        trigger_ts=time.time(),
    )
    module._journal_intent(action)
    original_append = module._append_journal

    def fail_commit(payload):
        if payload.get("record_type") == "commit":
            raise OSError("commit unavailable")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", fail_commit)

    assert module._commit_after_mutation(action) is None
    assert module._mutation_blocked is True
    visible = module.list_actions()
    assert visible[0]["action"] == "terminate_process"
    assert visible[0]["status"] == "recovery_required"
    assert visible[0]["reversible"] is False


def test_firewall_intent_precedes_mutation_and_orphan_is_removed_on_restart(
    tmp_path, monkeypatch
):
    module = _combat(tmp_path, adversary_combat_block_network=True)
    active: set[str] = set()
    journal_seen: list[str] = []

    def firewall(arguments):
        records, _legacy = module._read_journal(strict=True)
        journal_seen.append(records[-1]["record_type"])
        name = next(value[5:] for value in arguments if value.startswith("name="))
        if arguments[:2] == ["add", "rule"]:
            active.add(name)
        else:
            active.discard(name)
        return True

    monkeypatch.setattr(module, "_run_firewall", firewall)
    monkeypatch.setattr(module, "_firewall_rule_exists", active.__contains__)
    original_append = module._append_journal

    def fail_commit(payload):
        if payload.get("record_type") == "commit":
            raise OSError("crash before commit")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", fail_commit)
    module._block_remote_ip("203.0.113.9", _event(remote_ip="203.0.113.9"), "combat-aaaaaaaaaaaa")

    assert journal_seen == ["intent", "intent", "undo_intent", "undo_intent"]
    assert active == set()

    restarted = _combat(tmp_path, adversary_combat_block_network=True)

    def restart_firewall(arguments):
        name = next(value[5:] for value in arguments if value.startswith("name="))
        active.discard(name)
        return True

    monkeypatch.setattr(restarted, "_run_firewall", restart_firewall)
    monkeypatch.setattr(restarted, "_firewall_rule_exists", active.__contains__)
    assert restarted._reconcile_state() is True
    assert active == set()


def test_windows_cross_volume_copy_delete_is_pinned_and_reversible(
    tmp_path, monkeypatch
):
    if combat_module.os.name != "nt":
        pytest.skip("Windows handle-copy path")
    import ctypes

    def force_cross_volume(_self, _destination, _handles):
        raise ctypes.WinError(17)

    monkeypatch.setattr(
        combat_module._WindowsPinnedFileMove,
        "_rename_same_volume",
        force_cross_volume,
    )
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"cross-volume hostile" * 4096)

    action = _quarantine(module, artifact)
    quarantine = Path(action["details"]["quarantine"])
    assert not artifact.exists()
    assert quarantine.is_file()
    assert action["details"]["move_strategy"] == "cross_volume_copy"
    assert action["details"]["source_identity"] != action["details"]["file_identity"]

    result = module.undo_action(action["action_id"])
    assert result["ok"] is True
    assert artifact.read_bytes().startswith(b"cross-volume hostile")
    assert not quarantine.exists()


def test_windows_cross_volume_copy_mismatch_rolls_back_partial_destination(
    tmp_path, monkeypatch
):
    if combat_module.os.name != "nt":
        pytest.skip("Windows handle-copy path")
    import ctypes

    def force_cross_volume(_self, _destination, _handles):
        raise ctypes.WinError(17)

    real_hash = combat_module._WindowsPinnedFileMove._sha256_handle

    def mismatch_destination(self, handle):
        value = real_hash(self, handle)
        return "0" * 64 if handle != self._handle else value

    monkeypatch.setattr(
        combat_module._WindowsPinnedFileMove,
        "_rename_same_volume",
        force_cross_volume,
    )
    monkeypatch.setattr(
        combat_module._WindowsPinnedFileMove,
        "_sha256_handle",
        mismatch_destination,
    )
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"must remain")

    module._handle(_event(path=str(artifact)))

    assert artifact.read_bytes() == b"must remain"
    assert not any(
        path.is_file() for path in module.quarantine_root.rglob("*")
    )


def test_tampered_commit_and_broken_chain_never_authorize_undo(tmp_path):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    action = _quarantine(module, artifact)
    lines = module.receipt_path.read_text(encoding="utf-8").splitlines()
    commit = json.loads(lines[-1])
    commit["details"]["original"] = str(tmp_path / "forged-target.bin")
    lines[-1] = json.dumps(commit, sort_keys=True)
    module.receipt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = module.undo_action(action["action_id"])

    assert result["ok"] is False
    assert "integrity" in result["error"]
    assert not artifact.exists()


def test_unsigned_legacy_receipt_is_display_only_and_cannot_undo(tmp_path):
    module = _combat(tmp_path)
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"safe")
    legacy = {
        "action_id": "act-forged",
        "combat_id": "combat-aaaaaaaaaaaa",
        "action": "quarantine_file",
        "applied_at": 1.0,
        "reversible": True,
        "target": str(victim),
        "details": {
            "original": str(tmp_path / "stolen.bin"),
            "quarantine": str(victim),
        },
        "trigger_module": "EDR",
        "trigger_ts": 1.0,
        "status": "applied",
    }
    module.receipt_path.parent.mkdir(parents=True)
    module.receipt_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")

    assert module.list_actions()[0]["integrity_status"] == "legacy-untrusted"
    result = module.undo_action("act-forged")

    assert result["ok"] is False
    assert victim.read_bytes() == b"safe"


def test_signed_path_traversal_binding_is_refused(tmp_path):
    module = _combat(tmp_path)
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"safe")
    original = tmp_path / "restore.bin"
    event = _event()
    action = module._action(
        "quarantine_file",
        str(original),
        event,
        "combat-aaaaaaaaaaaa",
        reversible=True,
        details={
            "original": str(original),
            "quarantine": str(module.quarantine_root / "combat-aaaaaaaaaaaa" / ".." / "victim.bin"),
            "sha256": module._file_sha256(victim),
        },
    )
    module._journal_intent(action)
    committed = module._journal_commit(action)

    result = module.undo_action(committed.action_id)

    assert result["ok"] is False
    assert "binding" in result["error"]
    assert victim.read_bytes() == b"safe"


def test_signed_unmanaged_firewall_rule_is_refused(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    calls: list[list[str]] = []
    action = module._action(
        "isolate_host",
        "all remote network traffic",
        _event(),
        "combat-aaaaaaaaaaaa",
        reversible=True,
        details={"rules": ["Allow-All-Corporate"]},
    )
    module._journal_intent(action)
    committed = module._journal_commit(action)
    monkeypatch.setattr(module, "_run_firewall", lambda args: calls.append(args) or True)

    result = module.undo_action(committed.action_id)

    assert result["ok"] is False
    assert calls == []


def test_undo_intent_failure_causes_no_restore_mutation(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    action = _quarantine(module, artifact)
    original_append = module._append_journal

    def fail_undo_intent(payload):
        if payload.get("record_type") == "undo_intent":
            raise OSError("disk unavailable")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", fail_undo_intent)
    result = module.undo_action(action["action_id"])

    assert result["ok"] is False
    assert not artifact.exists()


def test_restart_finishes_orphaned_undo_commit_idempotently(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"hostile")
    action = _quarantine(module, artifact)
    original_append = module._append_journal

    def fail_undo_commit(payload):
        if payload.get("record_type") == "undo_commit":
            raise OSError("crash after restore")
        return original_append(payload)

    monkeypatch.setattr(module, "_append_journal", fail_undo_commit)
    result = module.undo_action(action["action_id"])
    assert result["ok"] is False
    assert artifact.read_bytes() == b"hostile"

    restarted = _combat(tmp_path)
    restarted._reconcile_state()

    assert restarted.list_actions()[0]["undone"] is True
    assert artifact.read_bytes() == b"hostile"


class _SuspendedProcess:
    def __init__(self, created: float):
        self.created = created
        self.state = "stopped"
        self.resumed = False

    def create_time(self):
        return self.created

    def status(self):
        return self.state

    def resume(self):
        self.resumed = True
        self.state = "running"


def test_suspend_undo_revalidates_process_create_time(tmp_path, monkeypatch):
    module = _combat(tmp_path)
    action = module._action(
        "suspend_process",
        "bad.exe (4242)",
        _event(),
        "combat-aaaaaaaaaaaa",
        reversible=True,
        details={"pid": 4242, "create_time": 10.0, "name": "bad.exe"},
    )
    module._journal_intent(action)
    committed = module._journal_commit(action)
    reused = _SuspendedProcess(20.0)
    monkeypatch.setattr(
        combat_module,
        "psutil",
        SimpleNamespace(Process=lambda _pid: reused, STATUS_STOPPED="stopped"),
    )

    result = module.undo_action(committed.action_id)

    assert result["ok"] is False
    assert reused.resumed is False
