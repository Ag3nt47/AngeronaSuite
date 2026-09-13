"""Exact Defender channel admission and durable modern-reader regressions."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules import av_telemetry_bridge as defender


_KEY = b"m" * 32


def _xml(number: int, event_id: int = 1116) -> str:
    return (
        f'<Event xmlns="{defender._NS}"><System>'
        f'<Provider Name="{defender._DEFENDER_PROVIDER}"/>'
        f'<EventID>{event_id}</EventID><EventRecordID>{number}</EventRecordID>'
        '<TimeCreated SystemTime="2026-09-12T12:00:00.0000000Z"/>'
        f'<Channel>{defender._DEFENDER_CHANNEL}</Channel></System>'
        '<EventData><Data Name="Threat Name">Inert.Test.Fixture</Data>'
        '<Data Name="Path">C:\\Fixtures\\inert.txt</Data></EventData></Event>'
    )


class _NoMoreItems(Exception):
    winerror = 259


class _ModernAPI:
    EvtQueryChannelPath = 1
    EvtQueryForwardDirection = 0x100
    EvtQueryReverseDirection = 0x200
    EvtRenderEventXml = 1

    def __init__(self, records: dict[int, str]) -> None:
        self.records = records
        self.queries: list[tuple[str, int, str]] = []
        self.counts: list[int] = []
        self.closed: list[object] = []

    def OpenEventLog(self, *_args):
        pytest.fail("classic OpenEventLog can silently open Application")

    def EvtQuery(self, channel: str, flags: int, expression: str):
        assert channel == defender._DEFENDER_CHANNEL
        assert "EventID=" not in expression  # All IDs must advance custody in order.
        self.queries.append((channel, flags, expression))
        comparison, raw = re.search(r"EventRecordID (>=|>|=) (\d+)", expression).groups()
        value = int(raw)
        matching = [
            number for number in sorted(self.records, reverse=bool(flags & 0x200))
            if {">=": number >= value, ">": number > value, "=": number == value}[comparison]
        ]
        return SimpleNamespace(numbers=matching)

    def EvtNext(self, query, count: int):
        self.counts.append(count)
        if not query.numbers:
            raise _NoMoreItems("no retained matching records")
        numbers, query.numbers = query.numbers[:count], query.numbers[count:]
        return [SimpleNamespace(number=number) for number in numbers]

    def EvtRender(self, event, flag: int) -> str:
        assert flag == self.EvtRenderEventXml
        return self.records[event.number]

    def EvtClose(self, handle) -> None:
        self.closed.append(handle)


def _install(monkeypatch: pytest.MonkeyPatch, records: dict[int, str]) -> _ModernAPI:
    api = _ModernAPI(records)
    monkeypatch.setitem(sys.modules, "win32evtlog", api)
    return api


def _module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = defender.AVTelemetryBridgeModule(tmp_path, continuity_key=_KEY)
    module.bind(EventBus())
    monkeypatch.setattr(module, "sleep", lambda _seconds: module._stop.set())
    return module


def test_modern_source_queries_exact_channel_and_admits_all_record_ids(monkeypatch):
    api = _install(monkeypatch, {10: _xml(10, 5007), 12: _xml(12)})
    source = defender._DefenderEventLogSource()
    assert source.oldest_record_id() == 10
    assert source.newest_record_id() == 12  # Do not infer newest from count.
    records = source.read_after(9, 20)
    assert [item.RecordNumber for item in records] == [10, 12]
    assert records[0].EventID == 5007
    assert records[1].StringInserts == [_xml(12)]
    assert records[1].TimeGenerated == "2026-09-12T12:00:00.0000000Z"
    assert source.record_at(12).RecordNumber == 12
    assert all(channel == defender._DEFENDER_CHANNEL for channel, _, _ in api.queries)
    assert len(api.closed) == 9  # Five rendered events and four query handles.


def test_modern_source_eof_is_normal_and_batch_is_bounded(monkeypatch):
    api = _install(monkeypatch, {n: _xml(n, 5007) for n in range(1, 601)})
    source = defender._DefenderEventLogSource()
    records = source.read_after(0, 100_000)
    assert len(records) == 256
    assert records[-1].RecordNumber == 256
    assert source.read_after(600, 100) == []
    assert source.record_at(999) is None
    assert max(api.counts) <= 256
    empty = _install(monkeypatch, {})
    source = defender._DefenderEventLogSource()
    assert source.oldest_record_id() == source.newest_record_id() == 0
    assert len(empty.closed) == 2


def test_modern_anchor_rejects_different_record_returned_by_query(monkeypatch):
    _install(monkeypatch, {1: _xml(2)})
    with pytest.raises(ValueError, match="different anchor record"):
        defender._DefenderEventLogSource().record_at(1)


@pytest.mark.parametrize("bad_xml", [
    "<Event>",
    _xml(1).replace(defender._DEFENDER_CHANNEL, "Application"),
    _xml(1).replace(f'Name="{defender._DEFENDER_PROVIDER}"', 'Name="Other.Provider"'),
    _xml(1).replace("<EventRecordID>1", "<EventRecordID>-1"),
    _xml(1).replace("<EventRecordID>1", f"<EventRecordID>{2**63}"),
    _xml(1).replace("<EventID>1116", "<EventID>65536"),
    _xml(1).replace("</System>", "<EventRecordID>2</EventRecordID></System>"),
    _xml(1).replace('SystemTime="2026-09-12T12:00:00.0000000Z"', ""),
    '<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///inert-test">]>' + _xml(1),
    "x" * (1024 * 1024 + 1),
], ids=[
    "malformed", "wrong-channel", "wrong-provider", "negative-id", "large-id",
    "large-eid", "duplicate-id", "missing-timestamp", "external-entity", "oversized",
])
def test_modern_source_rejects_malformed_or_wrong_identity_before_admission(bad_xml):
    with pytest.raises(ValueError):
        defender._DefenderEventLogSource._record(bad_xml)


def test_modern_reader_retains_correct_anchor_across_restart(tmp_path, monkeypatch):
    _install(monkeypatch, {3: _xml(3, 5007), 4: _xml(4)})
    first = _module(tmp_path, monkeypatch)
    assert first._try_evtlog_mode() is True
    assert first._current_record_id() == 4
    assert first._delivered == 1 and first._skipped == 1
    assert first.health == 100
    restarted = _module(tmp_path, monkeypatch)
    assert restarted._try_evtlog_mode() is True
    assert restarted._current_record_id() == 4
    assert restarted._delivered == 0
    assert restarted.health == 100


def test_missing_modern_api_never_uses_classic_application_fallback(tmp_path, monkeypatch):
    class LegacyOnly:
        def OpenEventLog(self, *_args):
            pytest.fail("Application fallback must never be opened")

    monkeypatch.setitem(sys.modules, "win32evtlog", LegacyOnly())
    assert _module(tmp_path, monkeypatch)._try_evtlog_mode() is False


def test_wrong_native_channel_blocks_fallback_and_retains_identity_diagnostic(tmp_path, monkeypatch):
    _install(monkeypatch, {1: _xml(1).replace(defender._DEFENDER_CHANNEL, "Application")})
    module = _module(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "_try_powershell_mode", lambda: pytest.fail("unsafe fallback"))
    module.run()
    assert module.health == 20
    assert "identity validation failed" in module.health_note
    assert module._checkpoint is None
    assert module.self_test()[0] is False


def test_explicit_restart_rechecks_previously_unavailable_continuity_authority(tmp_path, monkeypatch):
    _install(monkeypatch, {1: _xml(1)})
    module = _module(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "_continuity_key", lambda: None)
    monkeypatch.setattr(module, "_try_powershell_mode", lambda: pytest.fail("unsafe fallback"))
    module.run()
    assert module.health == 20
    assert "continuity authority is unavailable" in module.health_note
    module._stop.clear()
    monkeypatch.setattr(module, "_continuity_key", lambda: _KEY)
    module.run()
    assert module._current_record_id() == 1
    assert module.health == 100


@pytest.mark.parametrize("native_available", [True, False])
def test_custody_failure_preserves_actionable_error_without_retrying_fallback(
    tmp_path, monkeypatch, native_available,
):
    first = _module(tmp_path, monkeypatch)
    assert first._open_continuity_state() is True
    first._close_continuity_state()
    first._outbox_enrollment_path.write_text("{}", encoding="utf-8")
    _install(monkeypatch, {1: _xml(1)})
    module = _module(tmp_path, monkeypatch)
    if native_available:
        monkeypatch.setattr(module, "_try_powershell_mode", lambda: pytest.fail("unsafe fallback"))
    else:
        monkeypatch.setattr(module, "_try_evtlog_mode", lambda: False)
        monkeypatch.setattr(module, "_poll_ps", lambda: [])
    module.run()
    assert "outbox authentication/enrollment failed" in module.health_note
    assert module.health == 45
    assert module.self_test()[0] is False


def test_channel_generation_regression_never_reads_or_rebases_cursor(tmp_path, monkeypatch):
    first = _module(tmp_path, monkeypatch)
    assert first._open_continuity_state() is True
    first._stage_native_record(defender._DefenderEventLogSource._record(_xml(50)))
    first._close_continuity_state()
    api = _install(monkeypatch, {1: _xml(1)})
    module = _module(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "_try_powershell_mode", lambda: pytest.fail("unsafe fallback"))
    module.run()
    assert module._current_record_id() == 50
    assert "numbering regressed" in module.health_note
    assert "explicit continuity recovery" in module.health_note
    assert not any("EventRecordID > " in expression for _, _, expression in api.queries)


@pytest.mark.parametrize("oldest,newest", [(5, 3), (0, 3)])
def test_inconsistent_channel_bounds_halt_before_reading(tmp_path, monkeypatch, oldest, newest):
    source = SimpleNamespace(
        oldest_record_id=lambda: oldest,
        newest_record_id=lambda: newest,
        close=lambda: None,
        read_after=lambda *_args: pytest.fail("unverified bounds were read"),
    )
    monkeypatch.setattr(defender, "_DefenderEventLogSource", lambda: source)
    module = _module(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "_try_powershell_mode", lambda: pytest.fail("unsafe fallback"))
    module.run()
    assert module._current_record_id() == 0
    assert "bounds/anchor verification failed" in module.health_note
    assert module.self_test()[0] is False


def test_malformed_page_does_not_advance_or_scan_past_record(tmp_path, monkeypatch):
    api = _install(monkeypatch, {1: _xml(1), 2: "<Event>", 3: _xml(3)})
    module = _module(tmp_path, monkeypatch)
    assert module._try_evtlog_mode() is True
    assert module._current_record_id() == 0
    assert module._delivered == 0
    assert module.health < 70
    assert sum("EventRecordID > " in expression for _, _, expression in api.queries) == 1


def test_unacknowledged_record_stops_native_page_before_next_record(tmp_path, monkeypatch):
    _install(monkeypatch, {1: _xml(1), 2: _xml(2)})
    module = _module(tmp_path, monkeypatch)
    staged: list[int] = []
    monkeypatch.setattr(module, "_stage_native_record", lambda record: staged.append(record.RecordNumber))
    assert module._try_evtlog_mode() is True
    assert staged == [1]
    assert module._current_record_id() == 0


def test_fallback_empty_result_is_available_with_honest_degraded_coverage(tmp_path, monkeypatch):
    observed_commands = []

    def empty_poll(command, **_kwargs):
        observed_commands.append(command)
        return "\r\n  "

    monkeypatch.setattr(defender, "check_output_hidden", empty_poll)
    module = _module(tmp_path, monkeypatch)
    assert module._try_powershell_mode() is True
    assert module.health == 70
    ok, note = module.self_test()
    assert ok is True
    assert "degraded coverage" in note and "real-time EID coverage remains unavailable" in note
    assert "-ErrorAction Stop" in observed_commands[0][-1]


def test_native_empty_channel_is_available_without_claiming_anchored_history(tmp_path, monkeypatch):
    _install(monkeypatch, {})
    module = _module(tmp_path, monkeypatch)
    assert module._try_evtlog_mode() is True
    assert module._current_record_id() == 0
    assert module.health == 70
    assert "not yet anchored" in module.health_note
    assert module.self_test()[0] is True


def test_fallback_does_not_mask_persisted_continuity_gap(tmp_path, monkeypatch):
    first = _module(tmp_path, monkeypatch)
    assert first._open_continuity_state() is True
    first._stage_native_record(defender._DefenderEventLogSource._record(_xml(1)))
    first._continuity_gap("inert retained-history gap", reason_code="defender.test.gap")
    first._close_continuity_state()
    module = _module(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "_poll_ps", lambda: [])
    assert module._try_powershell_mode() is True
    assert module.health == 45
    assert "gap" in module.health_note
    assert module.self_test()[0] is False


def test_native_backlog_commits_bounded_filtered_pages_then_returns_to_idle(tmp_path, monkeypatch):
    api = _install(monkeypatch, {n: _xml(n, 5007) for n in range(1, 6)})
    monkeypatch.setattr(defender, "_MAX_NATIVE_BATCH", 2)
    module = _module(tmp_path, monkeypatch)
    delays = []
    committed = []
    original_commit = module._commit_checkpoint

    def commit(number, anchor):
        committed.append(number)
        return original_commit(number, anchor)

    def sleep(seconds):
        delays.append(seconds)
        assert len(delays) <= 4, "backlog reader did not return to idle"
        if seconds == defender._POLL_INTERVAL:
            module._stop.set()

    monkeypatch.setattr(module, "_commit_checkpoint", commit)
    monkeypatch.setattr(module, "sleep", sleep)
    assert module._try_evtlog_mode() is True
    assert module._current_record_id() == 5
    assert module._skipped == 5
    assert committed == [2, 4, 5]  # One durable checkpoint per contiguous filtered run.
    assert delays == [defender._REPLAY_YIELD_INTERVAL] * 3 + [defender._POLL_INTERVAL]
    queries = [expression for _, _, expression in api.queries if "EventRecordID > " in expression]
    assert queries == [f"*[System[EventRecordID > {n}]]" for n in (0, 2, 4, 5)]
    assert max(api.counts) <= 2
    restarted = _module(tmp_path, monkeypatch)
    assert restarted._try_evtlog_mode() is True
    assert restarted._current_record_id() == 5
    assert restarted._skipped == 0
    assert restarted.health == 100


@pytest.mark.parametrize("condition", ["empty", "error", "unacknowledged"])
def test_native_idle_error_and_blocked_ack_keep_normal_poll_delay(tmp_path, monkeypatch, condition):
    records = {} if condition == "empty" else {1: _xml(1), 2: _xml(2, 5007)}
    _install(monkeypatch, records)
    module = _module(tmp_path, monkeypatch)
    delays = []
    staged = []

    def sleep(seconds):
        delays.append(seconds)
        module._stop.set()

    monkeypatch.setattr(module, "sleep", sleep)
    if condition == "error":
        def fail_read(*_args):
            raise OSError("inert event reader failure")

        monkeypatch.setattr(defender._DefenderEventLogSource, "read_after", fail_read)
    elif condition == "unacknowledged":
        monkeypatch.setattr(
            module, "_stage_native_record", lambda record: staged.append(record.RecordNumber)
        )
    assert module._try_evtlog_mode() is True
    assert delays == [defender._POLL_INTERVAL]
    assert module._current_record_id() == 0
    assert module._skipped == 0
    if condition == "unacknowledged":
        assert staged == [1]


def test_filtered_run_flushes_before_detection_ack_and_after_it(tmp_path, monkeypatch):
    _install(monkeypatch, {
        1: _xml(1, 5007), 2: _xml(2, 5007), 3: _xml(3), 4: _xml(4, 5007),
    })
    module = _module(tmp_path, monkeypatch)
    committed = []
    observed = []
    original_commit = module._commit_checkpoint
    original_stage = module._stage_native_record

    def commit(number, anchor):
        committed.append(number)
        return original_commit(number, anchor)

    def stage(record):
        observed.append((record.RecordNumber, module._current_record_id()))
        original_stage(record)

    monkeypatch.setattr(module, "_commit_checkpoint", commit)
    monkeypatch.setattr(module, "_stage_native_record", stage)
    assert module._try_evtlog_mode() is True
    assert observed == [(3, 2)]
    assert committed == [2, 3, 4]
    assert module._current_record_id() == 4
    assert module._delivered == 1 and module._skipped == 3


def test_filtered_run_never_checkpoints_past_unacknowledged_detection(tmp_path, monkeypatch):
    _install(monkeypatch, {1: _xml(1, 5007), 2: _xml(2), 3: _xml(3, 5007)})
    module = _module(tmp_path, monkeypatch)
    staged = []
    monkeypatch.setattr(module, "_stage_native_record", lambda record: staged.append(record.RecordNumber))
    assert module._try_evtlog_mode() is True
    assert staged == [2]
    assert module._current_record_id() == 1
    assert module._skipped == 1


def test_filtered_record_gap_does_not_commit_any_part_of_run(tmp_path, monkeypatch):
    _install(monkeypatch, {1: _xml(1, 5007), 3: _xml(3, 5007)})
    module = _module(tmp_path, monkeypatch)
    assert module._try_evtlog_mode() is True
    assert module._current_record_id() == 0
    assert module._skipped == 0
    assert module.health < 70
    assert module._persisted_gap is True


def test_filtered_checkpoint_write_failure_retains_prior_cursor(tmp_path, monkeypatch):
    module = _module(tmp_path, monkeypatch)
    assert module._open_continuity_state() is True
    records = [defender._DefenderEventLogSource._record(_xml(n, 5007)) for n in (1, 2)]
    monkeypatch.setattr(module._checkpoint, "save", lambda *_args, **_kwargs: False)
    try:
        with pytest.raises(RuntimeError, match="could not be committed"):
            module._stage_native_page(records)
        assert module._current_record_id() == 0
        assert module._skipped == 0
    finally:
        module._close_continuity_state()


def test_interrupted_filtered_run_is_replayed_after_restart(tmp_path, monkeypatch):
    module = _module(tmp_path, monkeypatch)
    assert module._open_continuity_state() is True
    records = [defender._DefenderEventLogSource._record(_xml(n, 5007)) for n in (1, 2)]
    original_decode = module._decode_record

    def interrupted_decode(record):
        if record.RecordNumber == 2:
            module._stop.set()
        return original_decode(record)

    monkeypatch.setattr(module, "_decode_record", interrupted_decode)
    try:
        assert module._stage_native_page(records) is False
        assert module._current_record_id() == 0
        assert module._skipped == 0
    finally:
        module._close_continuity_state()
    _install(monkeypatch, {n: _xml(n, 5007) for n in (1, 2)})
    restarted = _module(tmp_path, monkeypatch)
    assert restarted._try_evtlog_mode() is True
    assert restarted._current_record_id() == 2
    assert restarted._skipped == 2


def test_filtered_run_cannot_admit_detection_without_ack(tmp_path, monkeypatch):
    module = _module(tmp_path, monkeypatch)
    assert module._open_continuity_state() is True
    try:
        records = [defender._DefenderEventLogSource._record(_xml(1))]
        with pytest.raises(ValueError, match="individual delivery acknowledgement"):
            module._checkpoint_filtered_run(records)
        assert module._current_record_id() == 0
    finally:
        module._close_continuity_state()
