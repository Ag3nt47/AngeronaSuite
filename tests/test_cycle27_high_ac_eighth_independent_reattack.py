from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from angerona.core.independent_high_water import CUSTODY_DOMAIN
from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import smart_deception
from angerona.modules.adversary_combat import CombatAction
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


def _reversible_combat_action() -> CombatAction:
    return CombatAction(
        action_id="act-1212121212121212",
        combat_id="combat-121212121212",
        action="block_remote_ip",
        applied_at=120.0,
        reversible=True,
        target="192.0.2.12",
        details={
            "remote_ip": "192.0.2.12",
            "rules": [
                "Angerona-Combat-IP-eighth-out",
                "Angerona-Combat-IP-eighth-in",
            ],
            "postcondition_verified": True,
        },
        trigger_module="inert-eighth-independent-reattack",
        trigger_ts=119.0,
        status="applied",
    )


def _enrolled_etw_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fake = _FakeEventLog([_FakeEventRecord(number) for number in range(1, 4)])
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    anchors: dict[str, str] = {}
    authority_key = b"R" * 32
    module = _etw(tmp_path, anchors, authority_key)
    assert [event["record"] for event in module._read_security_log()] == [1, 2, 3]
    assert _enroll_etw(module)["ok"] is True
    fake.records.extend(_FakeEventRecord(number) for number in range(4, 7))
    prepared = module._read_security_log()
    assert [event["record"] for event in prepared] == [4, 5, 6]
    assert module.security_delivery_outbox_path is not None
    assert module.security_delivery_outbox_path.exists()
    return fake, anchors, authority_key, module, prepared


def test_a01_duplicate_protected_authority_is_a_visible_fail_closed_error(
    tmp_path: Path,
) -> None:
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    anchors[module._recovery_anchor_name()] = '{"schema":2,"schema":2}'

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0
    assert "malformed" in restarted._journal_error


def test_a01_authenticated_anchor_numeric_fields_require_exact_integer_types(
    tmp_path: Path,
) -> None:
    """Red gate: authenticated authority must not normalize fractional fields."""
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    enrolled = module._recovery_anchor(allow_create=False)
    core = {key: value for key, value in enrolled.items() if key != "record_hmac"}
    core.update(
        {
            "schema": 2.0,
            "challenge_counter": 0.5,
            "last_journal_sequence": 0.5,
            "consumed_terminal_sequence": 0.5,
        }
    )
    encoded = module._encode_recovery_anchor(core)
    anchors[module._recovery_anchor_name()] = encoded
    module._write_recovery_witness(module._decode_recovery_anchor(encoded))

    restarted = _combat(tmp_path, anchors)
    assert restarted._reconcile_state() is False
    assert restarted._mutation_blocked is True
    assert restarted.health == 0


def test_a01_failed_undo_terminal_must_open_current_process_mutation_circuit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: an effect without its terminal must disarm before restart."""
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    action = _reversible_combat_action()
    module._journal_intent(action)
    module._journal_commit(action)
    original_append = module._append_undo_phase

    def fail_terminal(phase, record, undo_id, *, error="", recovery=False):
        if phase == "undo_commit":
            raise OSError("inert terminal durability loss")
        return original_append(
            phase,
            record,
            undo_id,
            error=error,
            recovery=recovery,
        )

    monkeypatch.setattr(module, "_append_undo_phase", fail_terminal)
    monkeypatch.setattr(module, "_undo_record", lambda _record: (True, ""))
    result = module.undo_action(action.action_id)

    assert result["ok"] is False
    assert "undo journal commit failed" in result["error"]
    records, _legacy = module._read_journal(strict=True)
    assert records[-1]["record_type"] == "undo_intent"
    assert module._mutation_blocked is True
    assert module.health == 0


def test_a01_restart_orphan_undo_keeps_journal_pinned_through_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: automatic restart compensation is also a host mutation."""
    anchors: dict[str, str] = {}
    module = _combat(tmp_path, anchors)
    assert module._reconcile_state() is True
    action = _reversible_combat_action()
    module._journal_intent(action)
    module._journal_commit(action)
    record, undone = module._trusted_action(action.action_id)
    assert record is not None and undone is False
    module._append_undo_phase(
        "undo_intent", record, "undo-3434343434343434"
    )

    restarted = _combat(tmp_path, anchors)
    effect_crossed = [False]

    def hostile_effect(_record):
        try:
            restarted.receipt_path.unlink()
        except OSError:
            return False, "journal custody denied the inert swap"
        effect_crossed[0] = True
        return True, ""

    monkeypatch.setattr(restarted, "_undo_record", hostile_effect)
    reconciled = restarted._reconcile_state()

    assert effect_crossed[0] is False
    assert restarted.receipt_path.exists()
    assert reconciled is True or (
        restarted._mutation_blocked is True and restarted.health == 0
    )


def test_a16_exact_ack_rejects_a_reordered_batch_and_retains_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake, anchors, authority_key, module, prepared = _enrolled_etw_batch(
        tmp_path, monkeypatch
    )

    with pytest.raises(ValueError, match="batch changed"):
        module._ack_security_delivery_outbox(list(reversed(prepared)))
    assert module.security_delivery_outbox_path is not None
    assert module.security_delivery_outbox_path.exists()

    restarted = _etw(tmp_path, anchors, authority_key)
    assert [event["record"] for event in restarted._read_security_log()] == [4, 5, 6]
    assert restarted.health < 100


def test_a16_ack_unlink_must_be_bound_to_the_verified_outbox_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: a pathname swap after verification must not count as ack."""
    _fake, _anchors, _authority_key, module, prepared = _enrolled_etw_batch(
        tmp_path, monkeypatch
    )
    path = module.security_delivery_outbox_path
    assert path is not None
    authentic_moved = path.with_name("inert-authentic-outbox-moved-aside.json")
    original_unlink = Path.unlink
    swapped = [False]

    def swap_at_unlink(self: Path, *args, **kwargs):
        if self == path and not swapped[0]:
            swapped[0] = True
            os.replace(path, authentic_moved)
            path.write_bytes(b"inert replacement")
            os.unlink(path)
            return None
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", swap_at_unlink)
    acknowledged = True
    try:
        module._ack_security_delivery_outbox(prepared)
    except ValueError:
        acknowledged = False

    assert not (acknowledged and authentic_moved.exists()), (
        "acknowledgement returned success after deleting a swapped pathname "
        "while the verified outbox object survived"
    )


def test_a16_missing_unacknowledged_outbox_must_not_be_silent_and_green(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: cursor-new/outbox-missing is ambiguous, never acknowledged."""
    _fake, anchors, authority_key, module, _prepared = _enrolled_etw_batch(
        tmp_path, monkeypatch
    )
    assert module.security_delivery_outbox_path is not None
    module.security_delivery_outbox_path.unlink()

    restarted = _etw(tmp_path, anchors, authority_key)
    replayed = restarted._read_security_log()

    safely_visible = bool(replayed) or (
        restarted.health < 100 and bool(restarted._security_gap)
    )
    assert safely_visible, (
        "advanced cursor plus missing unacknowledged outbox was accepted as "
        "healthy acknowledgement"
    )


@pytest.mark.parametrize(
    ("authority_object", "depth"),
    (("state", 4_000), ("witness", 2_000)),
)
def test_c03_deep_authority_json_must_not_escape_as_recursion_error(
    tmp_path: Path, authority_object: str, depth: int
) -> None:
    """Red gate: startup catches only OSError, so parsers must normalize depth."""
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    # The state object admits the real 8 KiB parser bomb; the 4 KiB witness
    # case separately proves its byte ceiling turns maximal nesting into an
    # ordinary fail-closed schema error.
    hostile = "[" * depth + "]" * depth
    path = (
        module._change_state_path()
        if authority_object == "state"
        else module._change_witness_path()
    )
    path.write_text(hostile, encoding="ascii")

    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = tmp_path / "state"
    with pytest.raises(OSError, match="unreadable"):
        restarted._load_change_state()


def test_c03_deadline_closes_held_iterator_and_reports_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Documents"
    root.mkdir()
    module = ransomware.RansomwareHeuristicsModule()
    clock = [100.0]
    closed = [False]

    def entries(*_args):
        try:
            for index in range(100):
                clock[0] += 0.1
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
        finally:
            closed[0] = True

    monkeypatch.setattr(ransomware, "TRAVERSAL_MAX_S", 0.25)
    monkeypatch.setattr(ransomware.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_held_directory_entries", entries)

    _rows, coverage = module._bounded_tree(root, 1_900_000_000.0)

    assert closed[0] is True
    assert int(coverage["truncated"]) >= 1
    assert coverage["collection_complete"] is False


def test_c03_deadline_and_stop_are_checked_before_requesting_next_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red gate: a held iterator must not start work after cancellation."""
    module = ransomware.RansomwareHeuristicsModule()
    produced = [0]

    def entries(*_args):
        produced[0] += 1
        yield (
            "blocked.bin",
            False,
            True,
            False,
            1,
            1.0,
            1,
            ("posix", 1, 2),
        )

    monkeypatch.setattr(module, "_held_directory_entries", entries)
    rows, truncated, eligible = module._fair_directory_entries(
        "posix",
        0,
        Path("."),
        ("posix", 1, 1),
        8,
        deadline=200.0,
        should_stop=lambda: True,
    )

    assert produced[0] == 0
    assert rows == []
    assert truncated is True
    assert eligible == 0


def test_c03_hostile_next_cannot_overrun_the_declared_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red gate documenting the platform-continuation requirement."""
    module = ransomware.RansomwareHeuristicsModule()
    clock = [100.0]

    def entries(*_args):
        clock[0] += 10.0
        yield (
            "slow.bin",
            False,
            True,
            False,
            1,
            1.0,
            1,
            ("posix", 1, 2),
        )

    monkeypatch.setattr(ransomware.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_held_directory_entries", entries)
    _rows, truncated, _eligible = module._fair_directory_entries(
        "posix",
        0,
        Path("."),
        ("posix", 1, 1),
        8,
        deadline=100.25,
        should_stop=lambda: False,
    )

    assert truncated is True
    assert clock[0] <= 100.25


def test_c03_genesis_intent_failure_does_not_strand_key_only_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: first-install crash must be recoverable or pre-authority."""
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    monkeypatch.setattr(
        module,
        "_write_change_transition",
        lambda **_kwargs: (_ for _ in ()).throw(
            OSError("inert genesis-intent persistence failure")
        ),
    )
    with pytest.raises(OSError, match="genesis-intent"):
        module._load_change_state()
    assert module._change_key_path().exists()
    assert module._change_enrollment_key_path().exists()
    assert not module._change_state_path().exists()
    assert not module._change_transition_path().exists()

    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = tmp_path / "state"
    restarted._load_change_state()
    assert restarted._change_state_loaded is True
    assert restarted._change_witness_verified is True


def _change_record(token: str, inode: int) -> dict[str, object]:
    return {
        "key": token * 64,
        "identity": ["posix", 1, inode],
        "path_sha256": token * 64,
        "size": 1,
        "modified_identity": inode,
        "content_sha256": token * 64,
        "content_complete": True,
    }


def test_c03_stale_writer_cannot_overwrite_a_competing_adjacent_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: witness check and intent install must be one writer CAS."""
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
    original_second_transition = second._write_change_transition
    interleaved = [False]

    def interleave_first_writer(**kwargs):
        if not interleaved[0]:
            interleaved[0] = True
            first._commit_change_cycle(complete=True)
        return original_second_transition(**kwargs)

    monkeypatch.setattr(second, "_write_change_transition", interleave_first_writer)
    with pytest.raises(OSError, match="writer|changed|pending|transition"):
        second._commit_change_cycle(complete=True)

    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = tmp_path / "state"
    restarted._load_change_state()
    assert "a" * 64 in restarted._change_receipts
    assert "b" * 64 not in restarted._change_receipts


def test_c03_hostile_witness_ahead_of_state_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    module._begin_change_cycle()
    original_write = module._write_change_state

    def fail_state(sequence, records, *, scan_epoch):
        if sequence == 1:
            raise OSError("inert before-state interruption")
        return original_write(sequence, records, scan_epoch=scan_epoch)

    monkeypatch.setattr(module, "_write_change_state", fail_state)
    with pytest.raises(OSError, match="before-state"):
        module._commit_change_cycle(complete=True)
    pending = module._read_change_transition()
    assert pending is not None
    module._write_change_witness(
        int(pending["new_sequence"]),
        int(pending["new_scan_epoch"]),
        str(pending["new_state_hmac"]),
    )

    restarted = ransomware.RansomwareHeuristicsModule()
    restarted._change_state_root = tmp_path / "state"
    with pytest.raises(OSError, match="predecessor witness"):
        restarted._load_change_state()


@pytest.mark.parametrize(
    ("authority_object", "depth"),
    (("transition", 4_000), ("witness", 2_000)),
)
def test_c13_deep_authority_json_must_not_escape_as_recursion_error(
    tmp_path: Path, authority_object: str, depth: int
) -> None:
    """Red gate for bounded transition and witness recovery objects."""
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    # The transition accepts the real 8 KiB parser bomb; the smaller witness
    # case proves its independent 4 KiB byte ceiling remains safely bounded.
    hostile = "[" * depth + "]" * depth
    path = (
        module._custody_transition_path()
        if authority_object == "transition"
        else module._custody_witness_path()
    )
    path.write_text(hostile, encoding="ascii")

    restarted = _smart(tmp_path, authority)
    with pytest.raises(OSError, match="unreadable"):
        restarted._load_custody_state(create=True)


def test_c13_local_only_genesis_crash_after_key_is_restart_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate for the default high_water=None launch configuration."""
    module = smart_deception.SmartDeception()
    module._runtime_root = tmp_path / "decoys"
    module._runtime_root.mkdir()

    def fail_after_key(**_kwargs):
        module._custody_key()
        raise OSError("inert local-genesis crash after key")

    monkeypatch.setattr(module, "_open_custody_ledger", fail_after_key)
    with pytest.raises(OSError, match="local-genesis"):
        module._load_custody_state(create=True)
    assert module._custody_key_path().exists()
    assert not module._custody_ledger_path().exists()
    assert not module._custody_transition_path().exists()

    restarted = smart_deception.SmartDeception()
    restarted._runtime_root = tmp_path / "decoys"
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_authority_initialized is True


def test_c13_head_reader_rejects_oversize_before_json_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: local head parsing needs an explicit byte ceiling."""
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    module._custody_head_path().write_text(" " * (128 * 1024), encoding="ascii")
    real_loads = smart_deception.json.loads
    parser_reached = [False]

    def bounded_loads(payload, *args, **kwargs):
        if len(payload) > 8 * 1024:
            parser_reached[0] = True
            raise AssertionError("oversize custody head reached JSON parser")
        return real_loads(payload, *args, **kwargs)

    monkeypatch.setattr(smart_deception.json, "loads", bounded_loads)
    with pytest.raises(OSError, match="unreadable|unsafe|byte"):
        module._read_custody_head()
    assert parser_reached[0] is False


def test_c13_ledger_authentication_does_not_materialize_all_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red gate: authenticate/cap incrementally instead of unbounded fetchall."""
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    real_open = module._open_custody_ledger
    fetchall_reached = [False]

    class CursorProxy:
        def __init__(self, cursor) -> None:
            self.cursor = cursor

        def __iter__(self):
            return iter(self.cursor)

        def fetchall(self):
            fetchall_reached[0] = True
            raise AssertionError("custody ledger used unbounded fetchall")

        def __getattr__(self, name):
            return getattr(self.cursor, name)

    class ConnectionProxy:
        def __init__(self, connection) -> None:
            self.connection = connection

        def execute(self, sql: str, *args):
            cursor = self.connection.execute(sql, *args)
            if "FROM custody_events ORDER BY sequence" in sql:
                return CursorProxy(cursor)
            return cursor

        def close(self) -> None:
            self.connection.close()

    def bounded_open(**kwargs):
        return ConnectionProxy(real_open(**kwargs))

    monkeypatch.setattr(module, "_open_custody_ledger", bounded_open)
    connection, _active = module._load_custody_state(create=True)
    connection.close()
    assert fetchall_reached[0] is False


def test_c13_missing_transition_after_sqlite_commit_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    original_head = module._write_custody_head

    def fail_new_head(sequence: int, head: str) -> None:
        if sequence == 1:
            raise OSError("inert post-SQLite interruption")
        original_head(sequence, head)

    monkeypatch.setattr(module, "_write_custody_head", fail_new_head)
    with pytest.raises(OSError, match="post-SQLite"):
        module._append_custody_state_event("pending_loss", "inert gap", (5, 6))
    assert module._custody_transition_path().exists()
    module._custody_transition_path().unlink()

    restarted = _smart(tmp_path, authority)
    with pytest.raises(OSError, match="rolled back|incomplete"):
        restarted._load_custody_state(create=True)
    assert authority.heads[CUSTODY_DOMAIN].revision == 1
    assert restarted._custody_freshness.independently_fresh is False


def test_c13_sqlite_precommit_failure_rolls_back_and_discards_exact_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = _IndependentMemoryHighWater()
    module = _smart(tmp_path, authority)
    _enroll_smart(module)
    original_load = module._load_custody_state

    class BeforeCommitFailure:
        def __init__(self, connection) -> None:
            self.connection = connection

        def execute(self, sql: str, *args):
            if sql == "COMMIT":
                raise OSError("inert precommit response")
            return self.connection.execute(sql, *args)

        def close(self) -> None:
            self.connection.close()

    def wrapped_load(**kwargs):
        connection, active = original_load(**kwargs)
        return BeforeCommitFailure(connection), active

    monkeypatch.setattr(module, "_load_custody_state", wrapped_load)
    with pytest.raises(OSError, match="precommit"):
        module._append_custody_state_event(
            "pending_loss", "inert precommit classification", (7, 8)
        )
    assert module._custody_transition_path().exists()

    restarted = _smart(tmp_path, authority)
    connection, _active = restarted._load_custody_state(create=True)
    connection.close()
    assert restarted._custody_ledger_sequence == 0
    assert restarted._custody_external_revision == 1
    assert restarted._custody_freshness.independently_fresh is True
    assert not restarted._custody_transition_path().exists()
