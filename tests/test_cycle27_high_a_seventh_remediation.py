from __future__ import annotations

import os
from pathlib import Path

import pytest

from angerona.core.eventbus import BusAuthority, EventBus
from angerona.modules import adversary_combat as combat_module
from angerona.modules.adversary_combat import (
    AdversaryCombat,
    CombatAction,
    JournalIntegrityError,
)
from angerona.modules.etw_listener import EtwListenerModule


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
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True

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
    committed = module._terminate_process_transaction(process, _action())

    assert process.delete_was_blocked is True
    assert committed is not None
    records, _legacy = module._read_journal(strict=True)
    assert [record["record_type"] for record in records] == ["intent", "commit"]
