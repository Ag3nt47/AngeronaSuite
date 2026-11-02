from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, EventBus
from angerona.modules import adversary_combat as combat_module
from angerona.modules.adversary_combat import (
    AdversaryCombat,
    CombatAction,
    JournalIntegrityError,
)
from angerona.modules.etw_listener import EtwListenerModule


@pytest.fixture
def inert_installed_authority(monkeypatch):
    """Admit only the explicitly requested inert host-effect fixture."""
    from angerona.core import breach_state

    monkeypatch.setattr(
        breach_state, "protect_authority", lambda: (True, "Inert installed native authority")
    )


def _combat(root: Path, anchors: dict[str, str]) -> AdversaryCombat:
    return AdversaryCombat(root, rollback_anchor=anchors)


def _action() -> CombatAction:
    return CombatAction(
        action_id="act-7777777777777777",
        combat_id="combat-777777777777",
        action="terminate_process",
        applied_at=100.0,
        reversible=False,
        target="4242",
        details={
            "pid": 4242,
            "create_time": 50.0,
            "mutation_generation": "7" * 32,
        },
        trigger_module="inert-seventh-remediation",
        trigger_ts=99.0,
    )


def _intent(module: AdversaryCombat) -> None:
    module._journal_intent(_action())


def _etw(
    root: Path, anchors: dict[str, str], authority_key: bytes
) -> EtwListenerModule:
    bus = EventBus(ring_size=32)
    bus.arm(BusAuthority(authority_key))
    module = EtwListenerModule(
        root,
        host_identity="cycle27-seventh-remediation-host",
        rollback_anchor=anchors,
    )
    module.bind(bus)
    return module


def test_missing_combat_witness_never_reauthorizes_legacy_snapshot(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    anchor = module._recovery_anchor(allow_create=False)
    legacy_core = {
        key: value for key, value in anchor.items() if key != "record_hmac"
    }
    legacy_core["schema"] = 1
    legacy_anchor = module._encode_recovery_anchor(legacy_core)
    legacy_journal = (
        module.receipt_path.read_bytes() if module.receipt_path.exists() else b""
    )

    _intent(module)
    module._mark_nonreversible_uncertain(_action(), "inert advanced mutation")
    module.recovery_witness_path.unlink()
    anchors[module._recovery_anchor_name()] = legacy_anchor
    module.receipt_path.write_bytes(legacy_journal)

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted.health == 0
    assert restarted._mutation_blocked is True
    assert "legacy" in restarted._journal_error.casefold()
    assert anchors[module._recovery_anchor_name()] == legacy_anchor
    assert not restarted.recovery_witness_path.exists()


def test_missing_etw_witness_never_reauthorizes_legacy_snapshot(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    authority_key = b"7" * 32
    module = _etw(tmp_path, anchors, authority_key)
    anchor = module._rollback_anchor(allow_create=True)
    legacy_core = {
        key: value for key, value in anchor.items() if key != "record_hmac"
    }
    legacy_core["schema"] = 1
    legacy_anchor = module._encode_rollback_anchor(legacy_core)
    advanced = {
        key: value for key, value in anchor.items() if key != "record_hmac"
    }
    advanced["revision"] = int(anchor["revision"]) + 1
    module._write_rollback_anchor(advanced)
    assert module.cursor_authority_witness_path is not None
    module.cursor_authority_witness_path.unlink()
    anchors[module._rollback_anchor_name()] = legacy_anchor

    restarted = _etw(tmp_path, anchors, authority_key)
    with pytest.raises(ValueError, match="legacy.*runtime authority"):
        restarted._rollback_anchor(allow_create=False)
    assert anchors[module._rollback_anchor_name()] == legacy_anchor
    assert restarted.cursor_authority_witness_path is not None
    assert not restarted.cursor_authority_witness_path.exists()


def test_deep_unsigned_journal_fails_closed_without_recursion_escape(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    module.receipt_path.parent.mkdir(parents=True)
    module.receipt_path.write_bytes(b"[" * 4_000 + b"]" * 4_000 + b"\n")

    assert module._reconcile_state() is False
    assert module.health == 0
    assert module._mutation_blocked is True
    assert "resource/schema" in module._journal_error


def test_journal_byte_budget_fails_closed_before_unbounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    module.receipt_path.parent.mkdir(parents=True)
    monkeypatch.setattr(combat_module, "_MAX_JOURNAL_BYTES", 1_024)
    module.receipt_path.write_bytes(b"x" * 1_025)

    assert module._reconcile_state() is False
    assert module.health == 0
    assert module._mutation_blocked is True


@pytest.mark.parametrize("swap_after_read", (1, 2))
def test_read_append_and_final_read_swaps_cannot_return_false_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap_after_read: int,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    original = module._read_journal
    calls = 0
    swap_succeeded = False
    alternate = b"inert alternate object\n"

    def read_then_swap(*, strict: bool = False):
        nonlocal calls, swap_succeeded
        result = original(strict=strict)
        if strict:
            calls += 1
        if strict and calls == swap_after_read:
            try:
                module.receipt_path.unlink()
                module.receipt_path.write_bytes(alternate)
                swap_succeeded = True
            except OSError:
                # Windows descriptor custody intentionally denies delete/replace.
                pass
        return result

    monkeypatch.setattr(module, "_read_journal", read_then_swap)
    error: JournalIntegrityError | None = None
    try:
        _intent(module)
    except JournalIntegrityError as exc:
        error = exc

    if swap_succeeded:
        assert error is not None
        assert module.receipt_path.read_bytes() == alternate
    else:
        assert error is None
        records, _legacy = original(strict=True)
        assert [record["record_type"] for record in records] == ["intent"]
    assert not (error is None and not module.receipt_path.exists())


@pytest.mark.skipif(os.name != "nt", reason="Windows host mutation custody contract")
def test_irreversible_effect_runs_while_canonical_journal_is_delete_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inert_installed_authority,
) -> None:
    import dataclasses
    import time

    from angerona.core import windows_process_lease as lease_module
    from angerona.core.eventbus import Event, Severity
    from angerona.core.response_contract import authorize_response
    from angerona.core.werfault_guard import OwnedProcessIdentity
    from angerona.core.windows_process_lease import ProcessObjectIdentity, WindowsProcessLease

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
    action = _action()
    action = dataclasses.replace(action, details={
        **action.details, "exe": r"C:\fixture\inert.exe",
    })

    class _InertProcess:
        delete_was_blocked = False

        def kill(self) -> None:
            try:
                module.receipt_path.unlink()
            except OSError:
                self.delete_was_blocked = True

        @staticmethod
        def wait(*, timeout: float) -> None:
            assert timeout == 3

        @staticmethod
        def is_running() -> bool:
            return False

    process = _InertProcess()
    boundary = []

    class _InertNative:
        """Only host operations are inert; real custody and authority remain."""
        identity_value = ProcessObjectIdentity(
            4242, 116444736500000000, r"c:\fixture\inert.exe",
        )

        def __init__(self):
            self.calls = []
            self.exited = False
            self.live_polls = 0
            self.authorized_poll = -1
            self.dispatch_guard_ran = False

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
            if not self.exited and milliseconds == 0:
                self.live_polls += 1
            if milliseconds > 0:
                process.wait(timeout=3)
            return self.exited

        def terminate(self, handle, code):
            assert (handle, code) == (101, 1)
            # The last native live poll belongs to WindowsProcessLease.terminate.
            # A successful original-event check must follow it before dispatch.
            assert self.live_polls >= 3
            assert self.authorized_poll == self.live_polls
            self.dispatch_guard_ran = True
            records, legacy = module._read_journal(strict=True)
            assert not legacy
            assert [record["record_type"] for record in records] == ["intent"]
            assert records[0]["action_id"] == action.action_id
            assert records[0]["details"]["native_pid"] == self.identity_value.pid
            assert records[0]["details"]["native_birth_ticks"] == self.identity_value.birth_ticks
            assert records[0]["details"]["native_image"] == self.identity_value.image
            boundary.append("durable-intent")
            self.calls.append(("terminate", handle, code))
            boundary.append("native-dispatch")
            process.kill()
            assert process.delete_was_blocked is True
            boundary.append("delete-blocked")
            self.exited = not process.is_running()

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
    leases = []
    original_acquire = module._acquire_termination_lease
    original_current_event = module._require_current_response_event

    def observe_current_event(candidate_event, **kwargs):
        result = original_current_event(candidate_event, **kwargs)
        assert candidate_event is event
        native.authorized_poll = native.live_polls
        return result

    def native_factory():
        factories.append(True)
        assert len(factories) == 1, "retained target was reopened"
        return native

    def observe_acquire(candidate_action):
        lease = original_acquire(candidate_action)
        assert type(lease) is WindowsProcessLease
        leases.append(lease)
        return lease

    monkeypatch.setattr(combat_module, "_WINDOWS_PROCESS_CUSTODY", True)
    monkeypatch.setattr(lease_module, "_Native", native_factory)
    monkeypatch.setattr(module, "_acquire_termination_lease", observe_acquire)
    monkeypatch.setattr(module, "_require_current_response_event", observe_current_event)
    event = Event(
        "inert-seventh-remediation", "Exact journal deletion custody control", Severity.HIGH,
        details={"pid": 4242, "process_create_time": 50.0,
                 **authorize_response(["terminate_process"], pid=4242, process_create_time=50.0)},
    )
    committed = module._terminate_process_transaction(process, action, event=event)

    assert len(leases) == 1
    assert leases[0].dispatch_started is True
    assert native.dispatch_guard_ran is True
    assert process.delete_was_blocked is True
    assert committed is not None
    records, _legacy = module._read_journal(strict=True)
    assert [record["record_type"] for record in records] == ["intent", "commit"]
    assert records[-1]["details"]["native_wait_signaled"] is True
    assert records[-1]["details"]["native_birth_ticks"] == native.identity_value.birth_ticks
    assert boundary == ["durable-intent", "native-dispatch", "delete-blocked", "native-close"]
    assert factories == [True]
    assert len(roster_reads) >= 2
    assert native.calls.count(("terminate", 101, 1)) == 1
    assert any(call[0] == "wait" and call[2] > 0 for call in native.calls)
    assert native.calls[-1] == ("close", 101)
    assert native.calls.count(("close", 101)) == 1
