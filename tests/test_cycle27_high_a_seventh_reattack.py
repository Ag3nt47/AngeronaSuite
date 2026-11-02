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


@pytest.fixture
def inert_installed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only requested effect tests model accepted authority; no real host effect."""
    from angerona.core import breach_state

    monkeypatch.setattr(breach_state, "protect_authority",
                        lambda: (True, "Inert installed native authority"))


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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inert_installed_authority,
) -> None:
    import time

    from angerona.core import windows_process_lease as lease_module
    from angerona.core.eventbus import Event, Severity
    from angerona.core.response_contract import authorize_response
    from angerona.core.werfault_guard import OwnedProcessIdentity
    from angerona.core.windows_process_lease import ProcessObjectIdentity
    from angerona.modules import adversary_combat as combat_module

    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    roster_reads = []

    def owned_processes():
        now = time.monotonic()
        roster_reads.append(now)
        return (OwnedProcessIdentity(
            65001, "116444737000000000", 100.0, r"C:\fixture\angerona-core.exe",
            "core", now, now + 5.0,
        ),)

    module.bind_manager(SimpleNamespace(
        modules={module.name: module}, owned_process_identities=owned_processes,
    ))
    assert module._reconcile_state() is True
    alias = tmp_path / "inert-journal-alias"
    action = _irreversible_action()
    action = dataclasses.replace(action, details={
        **action.details, "exe": r"C:\fixture\inert.exe",
    })
    boundary = []
    durable_intents = []
    circuit_observations = []

    class _InertNative:
        """Actual lease protocol; no OS process handle is opened or killed."""
        identity_value = ProcessObjectIdentity(
            4242, 116444736500000000, r"c:\fixture\inert.exe",
        )

        def __init__(self):
            self.calls = []
            self.exited = False
            self.link_added = False

        def open(self, pid, rights, inherit):
            assert (pid, rights, inherit) == (4242, lease_module._RIGHTS, False)
            self.calls.append(("open", pid, rights, inherit))
            return 101

        def identity(self, handle):
            assert handle == 101
            self.calls.append(("identity", handle))
            return self.identity_value

        def object_identity(self, handle):
            assert handle == 101
            self.calls.append(("object_identity", handle))
            return self.identity_value.pid, self.identity_value.birth_ticks

        def wait(self, handle, milliseconds):
            assert handle == 101 and 0 <= milliseconds <= 3000
            self.calls.append(("wait", handle, milliseconds))
            return self.exited

        def terminate(self, handle, code):
            assert (handle, code) == (101, 1)
            assert module._mutation_blocked is False
            assert not self.exited and not alias.exists()
            # Strict read authenticates the fsynced intent while the real
            # retained process lease and journal session are both still held.
            records, legacy = module._read_journal(strict=True)
            assert not legacy
            assert [record["record_type"] for record in records] == ["intent"]
            assert records[0]["action_id"] == action.action_id
            assert records[0]["details"]["native_pid"] == self.identity_value.pid
            assert records[0]["details"]["native_birth_ticks"] == self.identity_value.birth_ticks
            assert records[0]["details"]["native_image"] == self.identity_value.image
            durable_intents.extend(records)
            boundary.append("durable-intent")
            self.calls.append(("terminate", handle, code))
            boundary.append("native-dispatch")
            os.link(module.receipt_path, alias)
            self.link_added = True
            self.exited = True
            boundary.append("hardlink-added")

        def exit_code(self, handle):
            assert handle == 101 and self.exited
            self.calls.append(("exit_code", handle))
            return 1

        def close(self, handle):
            assert handle == 101
            self.calls.append(("close", handle))
            boundary.append("native-close")

    native = _InertNative()
    factories = []

    def native_factory():
        factories.append(True)
        assert len(factories) == 1, "retained target was reopened by another native observer"
        return native

    original_trip = module._trip_mutation_circuit

    def observe_circuit(record, reason, **kwargs):
        circuit_observations.append((native.link_added, native.exited))
        boundary.append("circuit")
        return original_trip(record, reason, **kwargs)

    # Exercise the real acquisition, exact-type custody, dispatch and terminal
    # barriers on every platform, with only the native operations made inert.
    monkeypatch.setattr(combat_module, "_WINDOWS_PROCESS_CUSTODY", True)
    monkeypatch.setattr(lease_module, "_Native", native_factory)
    monkeypatch.setattr(module, "_trip_mutation_circuit", observe_circuit)
    process = SimpleNamespace(kill=lambda: pytest.fail("PID-based termination fallback was used"))
    event = Event(
        "inert-seventh-reattack", "Exact inert termination control", Severity.HIGH,
        details={"pid": 4242, "process_create_time": 50.0,
                 **authorize_response(["terminate_process"], pid=4242, process_create_time=50.0)},
    )
    result = module._terminate_process_transaction(process, action, event=event)

    assert result is None
    assert len(durable_intents) == 1
    assert boundary[:3] == ["durable-intent", "native-dispatch", "hardlink-added"]
    assert circuit_observations and all(observation == (True, True) for observation in circuit_observations)
    assert boundary.index("hardlink-added") < boundary.index("circuit") < boundary.index("native-close")
    assert factories == [True]
    assert len(roster_reads) >= 2
    assert native.calls.count(("open", 4242, lease_module._RIGHTS, False)) == 1
    assert native.calls.count(("terminate", 101, 1)) == 1
    assert any(call[0] == "wait" and call[2] > 0 for call in native.calls)
    assert native.calls[-1] == ("close", 101)
    assert native.calls.count(("close", 101)) == 1
    assert module._mutation_blocked is True
    assert module.health == 0
    assert alias.samefile(module.receipt_path)
    assert module.receipt_path.stat().st_nlink == 2
    assert module._recovery_required[action.action_id]["status"] == "orphaned"
    with pytest.raises(JournalIntegrityError, match="combat journal object is unsafe"):
        module._read_journal(strict=True)


def test_operator_undo_retains_journal_custody_through_host_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inert_installed_authority,
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
    undo_entered = False

    def inert_undo(_record):
        nonlocal effect_crossed, undo_entered
        undo_entered = True
        # The exact journal remains pinned from undo intent through the host
        # reversal, so a competing removal attempt must fail closed.
        module.receipt_path.unlink()
        effect_crossed = True
        return True, ""

    monkeypatch.setattr(module, "_undo_record", inert_undo)
    result = module.undo_action(action.action_id)

    assert undo_entered, "the inert Undo did not enter the journal-custody boundary"
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
