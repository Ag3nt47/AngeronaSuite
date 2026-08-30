from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from angerona.core.eventbus import BusAuthority, EventBus
from angerona.modules.adversary_combat import (
    AdversaryCombat,
    CombatAction,
    JournalIntegrityError,
)
from angerona.modules.etw_listener import EtwListenerModule


def _combat(root: Path, anchor_store: dict[str, str]) -> AdversaryCombat:
    return AdversaryCombat(root, rollback_anchor=anchor_store)


def _intent(module: AdversaryCombat, suffix: str = "1") -> None:
    module._journal_intent(CombatAction(
        action_id=f"act-{suffix * 16}",
        combat_id=f"combat-{suffix * 12}",
        action="terminate_process",
        applied_at=100.0,
        reversible=False,
        target="4242",
        details={"pid": 4242, "create_time": 50.0},
        trigger_module="inert-sixth-remediation",
        trigger_ts=99.0,
    ))


def _legacy_combat_anchor(module: AdversaryCombat) -> str:
    anchor = module._recovery_anchor(allow_create=False)
    core = {key: value for key, value in anchor.items() if key != "record_hmac"}
    core["schema"] = 1
    return module._encode_recovery_anchor(core)


def _etw(
    root: Path, anchor_store: dict[str, str], authority_key: bytes
) -> EtwListenerModule:
    bus = EventBus(ring_size=32)
    bus.arm(BusAuthority(authority_key))
    module = EtwListenerModule(
        root,
        host_identity="cycle27-sixth-remediation-host",
        rollback_anchor=anchor_store,
    )
    module.bind(bus)
    return module


def _legacy_etw_anchor(module: EtwListenerModule) -> str:
    anchor = module._rollback_anchor(allow_create=False)
    core = {key: value for key, value in anchor.items() if key != "record_hmac"}
    core["schema"] = 1
    return module._encode_rollback_anchor(core)


def test_combat_legacy_replay_cannot_overwrite_surviving_newer_witness(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    legacy_anchor = _legacy_combat_anchor(module)

    _intent(module)
    module._mark_nonreversible_uncertain(
        CombatAction(
            action_id="act-1111111111111111",
            combat_id="combat-111111111111",
            action="terminate_process",
            applied_at=100.0,
            reversible=False,
            target="4242",
            details={"pid": 4242, "create_time": 50.0},
            trigger_module="inert-sixth-remediation",
            trigger_ts=99.0,
        ),
        "inert uncertain effect",
    )
    current_witness = module.recovery_witness_path.read_bytes()

    module.receipt_path.unlink()
    anchors[module._recovery_anchor_name()] = legacy_anchor
    restarted = _combat(tmp_path, anchors)

    assert restarted._reconcile_state() is False
    assert restarted.health == 0
    assert restarted._mutation_blocked is True
    assert "legacy" in restarted._journal_error.casefold()
    assert restarted.recovery_witness_path.read_bytes() == current_witness


def test_pre_witness_combat_anchor_requires_explicit_migration(tmp_path: Path) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    module._journal_key()
    core = module._initial_recovery_anchor()
    core["schema"] = 1
    anchors[module._recovery_anchor_name()] = module._encode_recovery_anchor(core)

    legacy = anchors[module._recovery_anchor_name()]

    assert module._reconcile_state() is False
    assert module.health == 0
    assert module._mutation_blocked is True
    assert "legacy" in module._journal_error.casefold()
    assert anchors[module._recovery_anchor_name()] == legacy
    assert module._read_recovery_witness() is None


def test_combat_duplicate_instance_writer_is_rejected_before_false_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchors: dict[str, str] = {}
    first = _combat(tmp_path, anchors)
    second = _combat(tmp_path, anchors)
    assert first._reconcile_state() is True
    entered = threading.Event()
    release = threading.Event()
    original_append = first._append_pinned_journal_bytes

    def append_then_hold(payload: bytes) -> None:
        original_append(payload)
        entered.set()
        assert release.wait(5.0)

    monkeypatch.setattr(first, "_append_pinned_journal_bytes", append_then_hold)
    first_error: list[BaseException] = []

    def write_first() -> None:
        try:
            _intent(first, "1")
        except BaseException as exc:  # pragma: no cover - assertion reports details
            first_error.append(exc)

    worker = threading.Thread(target=write_first, daemon=True)
    worker.start()
    assert entered.wait(5.0)
    with pytest.raises(JournalIntegrityError, match="writer lease"):
        _intent(second, "2")
    release.set()
    worker.join(5.0)

    assert not worker.is_alive()
    assert first_error == []
    records, _legacy = _combat(tmp_path, anchors)._read_journal(strict=True)
    assert [record["sequence"] for record in records] == [1]
    assert [record["action_id"] for record in records] == ["act-1111111111111111"]


def test_combat_hard_link_journal_is_rejected_without_append(tmp_path: Path) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    module.receipt_path.parent.mkdir(parents=True, exist_ok=True)
    unrelated = tmp_path / "unrelated-inert-file.txt"
    original = b"inert sentinel content\n"
    unrelated.write_bytes(original)
    try:
        os.link(unrelated, module.receipt_path)
    except OSError as exc:
        pytest.skip(f"hard links unavailable in this test environment: {exc}")

    with pytest.raises(JournalIntegrityError, match="unsafe"):
        _intent(module)

    assert unrelated.read_bytes() == original
    assert module.receipt_path.read_bytes() == original


def test_etw_legacy_replay_cannot_overwrite_surviving_newer_witness(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    authority_key = b"s" * 32
    module = _etw(tmp_path, anchors, authority_key)
    anchor = module._rollback_anchor(allow_create=True)
    legacy_anchor = _legacy_etw_anchor(module)
    advanced = {
        key: value for key, value in anchor.items() if key != "record_hmac"
    }
    advanced["revision"] = int(anchor["revision"]) + 1
    module._write_rollback_anchor(advanced)
    assert module.cursor_authority_witness_path is not None
    current_witness = module.cursor_authority_witness_path.read_bytes()

    anchors[module._rollback_anchor_name()] = legacy_anchor
    restarted = _etw(tmp_path, anchors, authority_key)

    with pytest.raises(ValueError, match="legacy.*runtime authority"):
        restarted._rollback_anchor(allow_create=False)
    assert restarted.cursor_authority_witness_path is not None
    assert restarted.cursor_authority_witness_path.read_bytes() == current_witness


def test_pre_witness_etw_anchor_requires_explicit_migration(tmp_path: Path) -> None:
    anchors: dict[str, str] = {}
    module = _etw(tmp_path, anchors, b"t" * 32)
    core = module._initial_rollback_anchor()
    core["schema"] = 1
    anchors[module._rollback_anchor_name()] = module._encode_rollback_anchor(core)

    legacy = anchors[module._rollback_anchor_name()]

    with pytest.raises(ValueError, match="legacy.*runtime authority"):
        module._rollback_anchor(allow_create=False)
    assert anchors[module._rollback_anchor_name()] == legacy
    assert module._read_authority_witness() is None
