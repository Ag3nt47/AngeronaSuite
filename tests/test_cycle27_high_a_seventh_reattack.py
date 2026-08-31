from __future__ import annotations

import dataclasses
import multiprocessing
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.authorization import (
    AuthorizationPolicy,
    AuthorizationRequest,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
)
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.modules.adversary_combat import (
    AdversaryCombat,
    CombatAction,
    JournalIntegrityError,
)
from angerona.modules.etw_listener import EtwListenerModule


def _combat(root: Path, anchors: dict[str, str]) -> AdversaryCombat:
    return AdversaryCombat(root, rollback_anchor=anchors)


def _irreversible_action() -> CombatAction:
    return CombatAction(
        action_id="act-8888888888888888",
        combat_id="combat-888888888888",
        action="terminate_process",
        applied_at=100.0,
        reversible=False,
        target="4242",
        details={
            "pid": 4242,
            "create_time": 50.0,
            "mutation_generation": "8" * 32,
        },
        trigger_module="inert-seventh-reattack",
        trigger_ts=99.0,
    )


def _hold_writer_lease(kind: str, path: str, ready, release) -> None:
    if kind == "combat":
        from angerona.modules.adversary_combat import _exclusive_combat_writer_lease

        lease = _exclusive_combat_writer_lease(Path(path))
    else:
        from angerona.modules.etw_listener import _exclusive_writer_lease

        lease = _exclusive_writer_lease(Path(path))
    with lease:
        ready.set()
        # The parent deliberately terminates this inert helper to model a
        # crashed writer and prove that the kernel releases its lease.
        release.wait(30.0)


@dataclasses.dataclass
class _FakeEventRecord:
    RecordNumber: int
    EventID: int = 4688
    TimeGenerated: str = "stable-generation"
    StringInserts: tuple[str, ...] = (r"C:\Windows\System32\cmd.exe",)
    SourceName: str = "Microsoft-Windows-Security-Auditing"
    ComputerName: str = "HOST"
    EventCategory: int = 0


class _FakeEventLog(SimpleNamespace):
    EVENTLOG_FORWARDS_READ = 1
    EVENTLOG_SEEK_READ = 2

    def __init__(self, records: list[_FakeEventRecord], page_size: int = 3) -> None:
        super().__init__()
        self.records = records
        self.page_size = page_size

    def OpenEventLog(self, _server, _channel):
        return self

    @staticmethod
    def CloseEventLog(_handle) -> None:
        return None

    def GetNumberOfEventLogRecords(self, _handle) -> int:
        return len(self.records)

    def GetOldestEventLogRecord(self, _handle) -> int:
        return min(record.RecordNumber for record in self.records)

    def ReadEventLog(self, _handle, _flags, offset: int):
        return [
            record for record in self.records if record.RecordNumber >= offset
        ][: self.page_size]


def _etw(
    root: Path, anchors: dict[str, str], authority_key: bytes
) -> EtwListenerModule:
    bus = EventBus(ring_size=64)
    bus.arm(BusAuthority(authority_key))
    module = EtwListenerModule(
        root,
        host_identity="cycle27-seventh-reattack-host",
        rollback_anchor=anchors,
    )
    module.bind(bus)
    return module


def _enroll(module: EtwListenerModule) -> dict[str, object]:
    policy = AuthorizationPolicy(
        (Principal("telemetry-operator", PrincipalKind.HUMAN),),
        (Role("telemetry-enroller", ("policy.approve",)),),
        (
            RoleBinding(
                "telemetry-operator",
                "telemetry-enroller",
                "telemetry/security-channel",
            ),
        ),
        b"seventh-reattack-etw-authorization-key" * 2,
    )
    module.bind_manager(
        SimpleNamespace(telemetry_enrollment_authorization_policy=policy)
    )
    reason = "Operator reviewed the exact inert Security channel boundary."
    resource = module.security_enrollment_resource(reason)
    assert resource
    decision = policy.decide(
        AuthorizationRequest(
            request_id="seventh-reattack-enrollment",
            principal_id="telemetry-operator",
            permission="policy.approve",
            scope="telemetry/security-channel",
            resource_id=resource,
        )
    )
    return module.enroll_security_cursor(decision=decision, reason=reason)


def test_existing_signing_key_does_not_prevent_three_object_authority_reset(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    signing_key = module.journal_key_path.read_bytes()

    action = _irreversible_action()
    module._journal_intent(action)
    module._mark_nonreversible_uncertain(action, "inert uncertain host effect")
    assert module._mutation_blocked is True

    module.receipt_path.unlink()
    module.recovery_witness_path.unlink()
    anchors.pop(module._recovery_anchor_name())

    restarted = _combat(tmp_path, anchors)
    assert restarted.journal_key_path.read_bytes() == signing_key
    assert restarted._reconcile_state() is True
    assert restarted._mutation_blocked is False
    assert restarted.health == 100
    assert restarted._pending_recovery_records() == {}


@pytest.mark.parametrize("keep_witness", (False, True))
def test_combat_schema_one_is_rejected_independent_of_witness_presence(
    tmp_path: Path, keep_witness: bool
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    anchor = module._recovery_anchor(allow_create=False)
    legacy = {key: value for key, value in anchor.items() if key != "record_hmac"}
    legacy["schema"] = 1
    anchors[module._recovery_anchor_name()] = module._encode_recovery_anchor(legacy)
    if not keep_witness:
        module.recovery_witness_path.unlink()

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert "legacy" in restarted._journal_error.casefold()


def test_deep_protected_recovery_anchor_opens_fail_closed_reconciliation(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    anchors[module._recovery_anchor_name()] = "[" * 4_000 + "]" * 4_000

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert "malformed" in restarted._journal_error


def test_deep_recovery_witness_opens_fail_closed_reconciliation(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    module.recovery_witness_path.write_text(
        "[" * 4_000 + "]" * 4_000,
        encoding="utf-8",
    )

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert "malformed" in restarted._journal_error


@pytest.mark.parametrize("boundary", ("before_anchor", "before_witness"))
def test_combat_partial_commit_positions_remain_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True

    def interrupted(*_args, **_kwargs):
        raise JournalIntegrityError(f"inert interruption {boundary}")

    if boundary == "before_anchor":
        monkeypatch.setattr(module, "_advance_recovery_anchor", interrupted)
    else:
        monkeypatch.setattr(module, "_write_recovery_witness", interrupted)

    with pytest.raises(JournalIntegrityError, match="inert interruption"):
        module._journal_intent(_irreversible_action())

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0


@pytest.mark.parametrize("kind", ("combat", "etw"))
def test_cross_process_writer_contention_and_crash_release(
    tmp_path: Path, kind: str
) -> None:
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    path = tmp_path / f"{kind}.writer.lock"
    process = context.Process(
        target=_hold_writer_lease,
        args=(kind, str(path), ready, release),
        daemon=True,
    )
    process.start()
    # Windows ``spawn`` can spend more than ten seconds importing the full test
    # environment on a contended host.  Keep this bounded while avoiding a
    # false lease failure before the child has reached the lease acquisition.
    assert ready.wait(30.0)
    try:
        if kind == "combat":
            from angerona.modules.adversary_combat import (
                _exclusive_combat_writer_lease,
            )

            with pytest.raises(JournalIntegrityError, match="writer lease"):
                with _exclusive_combat_writer_lease(path):
                    pass
        else:
            from angerona.modules.etw_listener import _exclusive_writer_lease

            with pytest.raises((OSError, RuntimeError)):
                with _exclusive_writer_lease(path):
                    pass
    finally:
        process.terminate()
        process.join(30.0)
    assert not process.is_alive()

    if kind == "combat":
        from angerona.modules.adversary_combat import _exclusive_combat_writer_lease

        with _exclusive_combat_writer_lease(path):
            pass
    else:
        from angerona.modules.etw_listener import _exclusive_writer_lease

        with _exclusive_writer_lease(path):
            pass


def test_hardlink_added_at_irreversible_effect_boundary_opens_circuit(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    alias = tmp_path / "inert-journal-alias"

    class _InertProcess:
        @staticmethod
        def kill() -> None:
            os.link(module.receipt_path, alias)

        @staticmethod
        def wait(*, timeout: float) -> None:
            assert timeout == 3

        @staticmethod
        def is_running() -> bool:
            return False

    result = module._terminate_process_transaction(
        _InertProcess(), _irreversible_action()
    )

    assert result is None
    assert module._mutation_blocked is True
    assert module.health == 0
    assert alias.samefile(module.receipt_path)


def test_operator_undo_retains_journal_custody_through_host_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    action = CombatAction(
        action_id="act-9999999999999999",
        combat_id="combat-999999999999",
        action="block_remote_ip",
        applied_at=100.0,
        reversible=True,
        target="192.0.2.99",
        details={
            "remote_ip": "192.0.2.99",
            "rules": ["Angerona-Combat-IP-audit-out", "Angerona-Combat-IP-audit-in"],
            "postcondition_verified": True,
        },
        trigger_module="inert-seventh-reattack",
        trigger_ts=99.0,
        status="applied",
    )
    module._journal_intent(action)
    module._journal_commit(action)
    effect_crossed = False

    def inert_undo(_record):
        nonlocal effect_crossed
        # The exact journal remains pinned from undo intent through the host
        # reversal, so a competing removal attempt must fail closed.
        module.receipt_path.unlink()
        effect_crossed = True
        return True, ""

    monkeypatch.setattr(module, "_undo_record", inert_undo)
    result = module.undo_action(action.action_id)

    assert effect_crossed is False
    assert result["ok"] is False
    assert result["error"]
    assert module.receipt_path.exists()
    assert module._mutation_blocked is False
    assert module.health == 100


def test_cursor_commit_before_event_delivery_replays_crashed_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeEventLog(
        [_FakeEventRecord(number) for number in range(1, 4)]
    )
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    anchors: dict[str, str] = {}
    authority_key = b"8" * 32
    module = _etw(tmp_path, anchors, authority_key)
    assert [event["record"] for event in module._read_security_log()] == [1, 2, 3]
    assert _enroll(module)["ok"] is True

    fake.records.extend(_FakeEventRecord(number) for number in range(4, 7))
    prepared_but_not_published = module._read_security_log()
    assert [event["record"] for event in prepared_but_not_published] == [4, 5, 6]

    # Simulate process loss after _read_security_log() durably advances the
    # cursor but before run() publishes its returned list to EventBus.
    restarted = _etw(tmp_path, anchors, authority_key)
    replayed = restarted._read_security_log()

    assert [event["record"] for event in replayed] == [4, 5, 6]
    assert restarted._last_record == 6
    assert restarted.health < 100
    assert restarted.security_delivery_outbox_path is not None
    assert restarted.security_delivery_outbox_path.exists()


@pytest.mark.parametrize(
    "boundary", ("after_highwater", "after_cursor", "after_anchor")
)
def test_etw_partial_commit_positions_replay_and_stay_degraded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    fake = _FakeEventLog(
        [_FakeEventRecord(number) for number in range(1, 4)]
    )
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    anchors: dict[str, str] = {}
    authority_key = b"8" * 32
    module = _etw(tmp_path, anchors, authority_key)
    assert [event["record"] for event in module._read_security_log()] == [1, 2, 3]
    assert _enroll(module)["ok"] is True

    if boundary == "after_highwater":
        original = module._append_highwater

        def append_then_fail(cursor):
            assert original(cursor) is True
            return False

        monkeypatch.setattr(module, "_append_highwater", append_then_fail)
    elif boundary == "after_cursor":
        monkeypatch.setattr(module, "_advance_rollback_anchor", lambda _cursor: False)
    else:
        monkeypatch.setattr(
            module,
            "_write_authority_witness",
            lambda _anchor: (_ for _ in ()).throw(
                RuntimeError("inert interruption after anchor")
            ),
        )

    fake.records.append(_FakeEventRecord(4))
    assert [event["record"] for event in module._read_security_log()] == [4]

    restarted = _etw(tmp_path, anchors, authority_key)
    replayed = restarted._read_security_log()
    assert [event["record"] for event in replayed] == [1, 2, 3, 4]
    assert restarted.health == 45
    assert restarted._security_gap


@pytest.mark.parametrize("keep_witness", (False, True))
def test_etw_schema_one_is_rejected_independent_of_witness_presence(
    tmp_path: Path, keep_witness: bool
) -> None:
    anchors: dict[str, str] = {}
    authority_key = b"8" * 32
    module = _etw(tmp_path, anchors, authority_key)
    anchor = module._rollback_anchor(allow_create=True)
    legacy = {key: value for key, value in anchor.items() if key != "record_hmac"}
    legacy["schema"] = 1
    anchors[module._rollback_anchor_name()] = module._encode_rollback_anchor(legacy)
    if not keep_witness:
        assert module.cursor_authority_witness_path is not None
        module.cursor_authority_witness_path.unlink()

    restarted = _etw(tmp_path, anchors, authority_key)
    with pytest.raises(ValueError, match="legacy.*runtime authority"):
        restarted._rollback_anchor(allow_create=False)
