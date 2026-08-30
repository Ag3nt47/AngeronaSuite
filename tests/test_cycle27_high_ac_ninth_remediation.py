"""Cycle 27 ninth defensive remediation regression gates.

All fixtures are inert and temporary.  No test performs a live host mutation.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import smart_deception
from angerona.modules.adversary_combat import JournalIntegrityError
from test_cycle27_high_ac_eighth_independent_reattack import (
    _change_record,
    _enrolled_etw_batch,
    _reversible_combat_action,
)
from test_cycle27_high_a_seventh_reattack import _combat, _etw
from test_cycle27_high_c_seventh_independent_reattack import (
    _IndependentMemoryHighWater,
    _enroll as _enroll_smart,
    _smart,
)


def test_a01_fractional_authenticated_authority_is_rejected(tmp_path: Path) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    enrolled = module._recovery_anchor(allow_create=False)
    core = {key: value for key, value in enrolled.items() if key != "record_hmac"}
    core["last_journal_sequence"] = 0.5
    with pytest.raises(JournalIntegrityError, match="values are invalid"):
        module._validated_recovery_anchor(module._encode_recovery_anchor(core))


def test_a01_terminal_loss_trips_current_process_circuit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    action = _reversible_combat_action()
    module._journal_intent(action)
    module._journal_commit(action)
    original = module._append_undo_phase

    def append(phase, record, undo_id, *, error="", recovery=False):
        if phase == "undo_commit":
            raise OSError("inert terminal loss")
        return original(phase, record, undo_id, error=error, recovery=recovery)

    monkeypatch.setattr(module, "_append_undo_phase", append)
    monkeypatch.setattr(module, "_undo_record", lambda _record: (True, ""))
    result = module.undo_action(action.action_id)
    assert result["ok"] is False
    assert module._mutation_blocked is True
    assert module.health == 0


def test_a01_restart_compensation_runs_inside_pinned_journal_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    action = _reversible_combat_action()
    module._journal_intent(action)
    module._journal_commit(action)
    record, _undone = module._trusted_action(action.action_id)
    assert record is not None
    module._append_undo_phase("undo_intent", record, "undo-5656565656565656")

    restarted = _combat(tmp_path, anchors)
    original_session = restarted._pinned_journal_session
    held = [False]
    observed = [False]

    @contextmanager
    def tracked_session(*args, **kwargs):
        with original_session(*args, **kwargs):
            held[0] = True
            try:
                yield
            finally:
                held[0] = False

    def inert_undo(_record):
        observed[0] = held[0]
        return True, ""

    monkeypatch.setattr(restarted, "_pinned_journal_session", tracked_session)
    monkeypatch.setattr(restarted, "_undo_record", inert_undo)
    assert restarted._reconcile_state() is True
    assert observed[0] is True


def test_a16_ack_receipt_matches_exact_committed_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake, _anchors, _key, module, prepared = _enrolled_etw_batch(
        tmp_path, monkeypatch
    )
    module._ack_security_delivery_outbox(prepared)
    assert module._security_delivery_ack_matches_cursor() is True
    assert module.security_delivery_outbox_path is not None
    assert not module.security_delivery_outbox_path.exists()
    assert module.security_delivery_custody_path is not None
    assert not module.security_delivery_custody_path.exists()


def test_a16_ack_claims_object_before_durable_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake, _anchors, _key, module, prepared = _enrolled_etw_batch(
        tmp_path, monkeypatch
    )
    original = module._write_security_delivery_ack
    claimed = [False]

    def observe_claim(outbox_record_hmac=""):
        assert module.security_delivery_outbox_path is not None
        assert module.security_delivery_custody_path is not None
        claimed[0] = (
            not module.security_delivery_outbox_path.exists()
            and module.security_delivery_custody_path.exists()
        )
        return original(outbox_record_hmac)

    monkeypatch.setattr(module, "_write_security_delivery_ack", observe_claim)
    module._ack_security_delivery_outbox(prepared)
    assert claimed[0] is True


def test_a16_cursor_without_ack_or_outbox_is_visible_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake, anchors, authority_key, module, _prepared = _enrolled_etw_batch(
        tmp_path, monkeypatch
    )
    assert module.security_delivery_outbox_path is not None
    module.security_delivery_outbox_path.unlink()
    restarted = _etw(tmp_path, anchors, authority_key)
    assert restarted._read_security_log() == []
    assert restarted.health < 100
    assert "acknowledgement" in restarted._security_gap


def test_c03_deep_state_json_is_normalized_to_oserror() -> None:
    hostile = ("[" * 4000 + "]" * 4000).encode("ascii")
    with pytest.raises(OSError, match="unreadable"):
        ransomware._bounded_change_json(
            hostile,
            label="durable content-state",
            max_bytes=ransomware.CHANGE_STATE_MAX_BYTES,
        )


def test_c03_stop_is_admitted_before_next(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ransomware.RansomwareHeuristicsModule()
    produced = [0]

    def entries(*_args):
        produced[0] += 1
        yield ("inert.bin", False, True, False, 1, 1.0, 1, ("posix", 1, 2))

    monkeypatch.setattr(module, "_held_directory_entries", entries)
    rows, truncated, eligible = module._fair_directory_entries(
        "posix",
        0,
        Path("."),
        ("posix", 1, 1),
        8,
        should_stop=lambda: True,
    )
    assert (rows, truncated, eligible, produced[0]) == ([], True, 0, 0)


def test_c03_short_deadline_refuses_blocking_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = ransomware.RansomwareHeuristicsModule()
    clock = [100.0]

    def entries(*_args):
        clock[0] += 10.0
        yield ("slow.bin", False, True, False, 1, 1.0, 1, ("posix", 1, 2))

    monkeypatch.setattr(ransomware.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_held_directory_entries", entries)
    _rows, truncated, _eligible = module._fair_directory_entries(
        "posix",
        0,
        Path("."),
        ("posix", 1, 1),
        8,
        deadline=100.1,
    )
    assert truncated is True
    assert clock[0] == 100.0


def test_c03_genesis_marker_recovers_key_only_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    monkeypatch.setattr(
        module,
        "_write_change_transition",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("inert genesis failure")),
    )
    with pytest.raises(OSError, match="genesis failure"):
        module._load_change_state()
    assert module._change_genesis_path().exists()
    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = tmp_path / "state"
    restarted._load_change_state()
    assert restarted._change_witness_verified is True
    assert not restarted._change_genesis_path().exists()


def test_c03_adjacent_commit_is_writer_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = ransomware.RansomwareHeuristicsModule()
    first._change_state_root = tmp_path / "state"
    first._load_change_state()
    second = ransomware.RansomwareHeuristicsModule()
    second._change_state_root = tmp_path / "state"
    second._load_change_state()
    first._begin_change_cycle()
    second._begin_change_cycle()
    first._change_observations = {"a" * 64: _change_record("a", 11)}
    second._change_observations = {"b" * 64: _change_record("b", 12)}
    original = second._write_change_transition

    def interleave(**kwargs):
        first._commit_change_cycle(complete=True)
        return original(**kwargs)

    monkeypatch.setattr(second, "_write_change_transition", interleave)
    with pytest.raises(OSError, match="writer|changed"):
        second._commit_change_cycle(complete=True)


def test_c13_deep_transition_is_normalized_to_oserror() -> None:
    hostile = ("[" * 4000 + "]" * 4000).encode("ascii")
    with pytest.raises(OSError, match="unreadable"):
        smart_deception._bounded_custody_json(
            hostile,
            label="pending custody transition",
            max_bytes=smart_deception._CUSTODY_OUTBOX_MAX_BYTES,
        )


def test_c13_local_genesis_marker_recovers_key_only_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = smart_deception.SmartDeception()
    module._runtime_root = tmp_path / "decoys"
    module._runtime_root.mkdir()

    def fail_after_key(**_kwargs):
        module._custody_key()
        raise OSError("inert local genesis")

    monkeypatch.setattr(module, "_open_custody_ledger", fail_after_key)
    with pytest.raises(OSError, match="local genesis"):
        module._load_custody_state(create=True)
    assert module._custody_local_genesis_path().exists()
    restarted = smart_deception.SmartDeception()
    restarted._runtime_root = tmp_path / "decoys"
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_authority_initialized is True


def test_c13_head_size_is_checked_before_json_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    module._custody_head_path().write_bytes(b" " * (128 * 1024))
    reached = [False]

    def forbidden(*_args, **_kwargs):
        reached[0] = True
        raise AssertionError("oversize object reached parser")

    monkeypatch.setattr(smart_deception.json, "loads", forbidden)
    with pytest.raises(OSError, match="unreadable"):
        module._read_custody_head()
    assert reached[0] is False


def test_c13_ledger_authentication_streams_bounded_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    real_open = module._open_custody_ledger
    saw_limit = [False]

    class CursorProxy:
        def __init__(self, cursor) -> None:
            self._cursor = cursor

        def __iter__(self):
            return iter(self._cursor)

        def fetchall(self):
            raise AssertionError("unbounded fetchall is forbidden")

        def __getattr__(self, name):
            return getattr(self._cursor, name)

    class ConnectionProxy:
        def __init__(self, connection) -> None:
            self._connection = connection

        def execute(self, sql: str, *args):
            cursor = self._connection.execute(sql, *args)
            if "FROM custody_events ORDER BY sequence" in sql:
                saw_limit[0] = "LIMIT ?" in sql
                return CursorProxy(cursor)
            return cursor

        def close(self) -> None:
            self._connection.close()

    def bounded_open(**kwargs):
        return ConnectionProxy(real_open(**kwargs))

    monkeypatch.setattr(module, "_open_custody_ledger", bounded_open)
    connection, _active = module._load_custody_state(create=True)
    connection.close()
    assert saw_limit[0] is True
