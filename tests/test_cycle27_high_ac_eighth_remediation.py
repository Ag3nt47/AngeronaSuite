from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

from angerona.core.independent_high_water import CUSTODY_DOMAIN
from angerona.modules import ransomware_heuristics as ransomware
from test_cycle27_high_a_seventh_reattack import (
    _FakeEventLog,
    _FakeEventRecord,
    _combat,
    _enroll as _enroll_etw,
    _etw,
)
from test_cycle27_high_c_seventh_independent_reattack import (
    _IndependentMemoryHighWater,
    _enroll as _enroll_smart,
    _smart,
)


@pytest.mark.parametrize("authority_object", ("anchor", "witness"))
def test_a01_deep_authority_json_opens_visible_circuit(
    tmp_path: Path, authority_object: str
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    hostile = "[" * 4_000 + "]" * 4_000
    if authority_object == "anchor":
        anchors[module._recovery_anchor_name()] = hostile
    else:
        module.recovery_witness_path.write_text(hostile, encoding="utf-8")

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert "malformed" in restarted._journal_error


def test_a16_unacknowledged_batch_replays_then_acknowledges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 4)])
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    anchors: dict[str, str] = {}
    authority_key = b"E" * 32
    module = _etw(tmp_path, anchors, authority_key)
    assert [event["record"] for event in module._read_security_log()] == [1, 2, 3]
    assert _enroll_etw(module)["ok"] is True

    fake.records.extend(_FakeEventRecord(number) for number in range(4, 7))
    prepared = module._read_security_log()
    assert [event["record"] for event in prepared] == [4, 5, 6]
    assert module.security_delivery_outbox_path is not None
    assert module.security_delivery_outbox_path.exists()

    restarted = _etw(tmp_path, anchors, authority_key)
    replayed = restarted._read_security_log()
    assert [event["record"] for event in replayed] == [4, 5, 6]
    assert restarted.health < 100
    restarted._ack_security_delivery_outbox(replayed)
    assert not restarted.security_delivery_outbox_path.exists()

    acknowledged = _etw(tmp_path, anchors, authority_key)
    assert acknowledged._read_security_log() == []
    assert acknowledged._last_record == 6


def test_a16_outbox_survives_cursor_commit_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 4)])
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    anchors: dict[str, str] = {}
    authority_key = b"F" * 32
    module = _etw(tmp_path, anchors, authority_key)
    module._read_security_log()
    assert _enroll_etw(module)["ok"] is True
    fake.records.append(_FakeEventRecord(4))
    monkeypatch.setattr(module, "_persist_cursor_state", lambda: False)

    assert [event["record"] for event in module._read_security_log()] == [4]
    assert module.security_delivery_outbox_path is not None
    assert module.security_delivery_outbox_path.exists()

    restarted = _etw(tmp_path, anchors, authority_key)
    assert [event["record"] for event in restarted._read_security_log()] == [4]
    assert restarted.health < 100


def test_c03_enumerator_honors_stop_during_held_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    module = ransomware.RansomwareHeuristicsModule()
    yielded = [0]

    def entries(*_args):
        for index in range(100):
            yielded[0] += 1
            if yielded[0] == 2:
                module._stop.set()
            yield (
                f"f{index:03}.bin",
                False,
                True,
                False,
                1,
                1.0,
                index + 1,
                ("posix", 1, index + 100),
            )

    monkeypatch.setattr(module, "_held_directory_entries", entries)
    _rows, coverage = module._bounded_tree(root, 1_900_000_000.0)

    assert yielded[0] == 2
    assert int(coverage["truncated"]) >= 1
    assert coverage["collection_complete"] is False


@pytest.mark.parametrize("boundary", ("before_state", "before_witness", "before_clear"))
def test_c03_adjacent_state_witness_transaction_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    module._begin_change_cycle()

    if boundary == "before_state":
        original = module._write_change_state

        def fail_state(sequence, records, *, scan_epoch):
            if sequence == 1:
                raise OSError("inert before-state crash")
            return original(sequence, records, scan_epoch=scan_epoch)

        monkeypatch.setattr(module, "_write_change_state", fail_state)
    elif boundary == "before_witness":
        monkeypatch.setattr(
            module,
            "_write_change_witness",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("inert before-witness crash")
            ),
        )
    else:
        monkeypatch.setattr(
            module,
            "_remove_change_transition",
            lambda: (_ for _ in ()).throw(OSError("inert before-clear crash")),
        )

    with pytest.raises(OSError, match="inert"):
        module._commit_change_cycle(complete=True)
    assert module._change_transition_path().exists()

    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = tmp_path / "state"
    restarted._load_change_state()
    expected_sequence = 0 if boundary == "before_state" else 1
    assert restarted._change_state_sequence == expected_sequence
    assert restarted._read_change_witness() == (
        restarted._change_state_sequence,
        restarted._change_scan_epoch,
        restarted._change_state_head,
    )
    assert not restarted._change_transition_path().exists()


@pytest.mark.parametrize(
    "boundary", ("before_ledger", "before_head", "before_witness", "authority_outage")
)
def test_c13_first_enrollment_recovers_each_durable_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)

    if boundary == "before_ledger":
        monkeypatch.setattr(
            module,
            "_open_custody_ledger",
            lambda **_kwargs: (_ for _ in ()).throw(
                OSError("inert before-ledger crash")
            ),
        )
    elif boundary == "before_head":
        monkeypatch.setattr(
            module,
            "_write_custody_head",
            lambda *_args: (_ for _ in ()).throw(OSError("inert before-head crash")),
        )
    elif boundary == "before_witness":
        monkeypatch.setattr(
            module,
            "_write_custody_witness",
            lambda *_args: (_ for _ in ()).throw(
                OSError("inert before-witness crash")
            ),
        )
    else:
        authority.fail_advances = 1

    with pytest.raises(OSError):
        module._load_custody_state(create=True)
    assert module._custody_transition_path().exists()

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_ledger_sequence == 0
    assert restarted._custody_external_revision == 1
    assert restarted._custody_freshness.independently_fresh is True
    assert not restarted._custody_transition_path().exists()


@pytest.mark.parametrize("boundary", ("after_commit", "after_head", "before_external"))
def test_c13_event_transition_repairs_local_metadata_and_external_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    if boundary == "after_commit":
        original = module._write_custody_head

        def fail_head(sequence: int, head: str) -> None:
            if sequence == 1:
                raise OSError("inert after-commit crash")
            original(sequence, head)

        monkeypatch.setattr(module, "_write_custody_head", fail_head)
    elif boundary == "after_head":
        original = module._write_custody_witness

        def fail_witness(sequence: int, head: str) -> None:
            if sequence == 1:
                raise OSError("inert after-head crash")
            original(sequence, head)

        monkeypatch.setattr(module, "_write_custody_witness", fail_witness)
    else:
        monkeypatch.setattr(
            module,
            "_advance_external_custody",
            lambda *_args: (_ for _ in ()).throw(
                OSError("inert before-external crash")
            ),
        )

    with pytest.raises(OSError, match="inert"):
        module._append_custody_state_event(
            "pending_loss", f"inert {boundary}", (7, 8)
        )
    assert module._custody_transition_path().exists()

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_ledger_sequence == 1
    assert restarted._custody_external_revision == 2
    assert authority.heads[CUSTODY_DOMAIN].revision == 2
    assert restarted._custody_freshness.independently_fresh is True
    assert not restarted._custody_transition_path().exists()


def test_c13_ambiguous_sqlite_commit_retains_reconcilable_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    original_load = module._load_custody_state

    class AmbiguousCommit:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(self, sql: str, *args):
            result = self.connection.execute(sql, *args)
            if sql == "COMMIT":
                raise sqlite3.OperationalError("inert committed response lost")
            return result

        def close(self) -> None:
            self.connection.close()

    def ambiguous_load(**kwargs):
        connection, active = original_load(**kwargs)
        return AmbiguousCommit(connection), active

    monkeypatch.setattr(module, "_load_custody_state", ambiguous_load)
    with pytest.raises(sqlite3.OperationalError, match="response lost"):
        module._append_custody_state_event(
            "pending_loss", "inert ambiguous commit", (9, 10)
        )
    assert module._custody_transition_path().exists()

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_ledger_sequence == 1
    assert restarted._custody_external_revision == 2
    assert not restarted._custody_transition_path().exists()
