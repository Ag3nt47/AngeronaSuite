"""Inert modern-channel snapshots; no native Event Log or response actions."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.event_log_integrity import ChannelCheckpoint
from angerona.modules import av_telemetry_bridge as defender


def _record(number, generation="first"):
    return SimpleNamespace(RecordNumber=number, EventID=5007,
                           TimeGenerated=generation,
                           StringInserts=[f"<inert generation='{generation}' id='{number}'/>"])


class _Source:
    def __init__(self, count=1):
        self.records = {number: _record(number) for number in range(1, count + 1)}
        self.after_read = lambda: None

    def newest_record_id(self):
        return max(self.records, default=0)

    def oldest_record_id(self):
        return min(self.records, default=0)

    def record_at(self, number):
        return self.records.get(number)

    def read_after(self, number, limit):
        rows = [self.records[key] for key in sorted(self.records) if key > number][:limit]
        self.after_read()
        return rows

    def close(self):
        pass


def _module(monkeypatch, tmp_path, source):
    monkeypatch.setattr(defender, "_DefenderEventLogSource", lambda: source)
    module = defender.AVTelemetryBridgeModule(tmp_path, continuity_key=b"k" * 32)
    module.bind(EventBus())
    return module


@pytest.mark.parametrize("replace_during_query", [False, True])
def test_live_generation_replacement_never_advances_old_checkpoint(
    monkeypatch, tmp_path, replace_during_query,
):
    source = _Source()
    module = _module(monkeypatch, tmp_path, source)
    ticks = []

    def replace():
        source.records = {number: _record(number, "replaced") for number in (1, 2)}

    def tick(_seconds):
        ticks.append(1)
        if len(ticks) == 1:
            assert module._current_record_id() == 1
            if replace_during_query:
                source.records[2] = _record(2)
                source.after_read = replace
            else:
                replace()
        else:
            module._stop.set()

    monkeypatch.setattr(module, "sleep", tick)
    module._try_evtlog_mode()
    assert module._current_record_id() == 1
    assert module._continuity_gaps > 0
    assert module._persisted_gap
    assert module._startup_blocked
    assert module.health < 100


def test_native_pagination_and_authenticated_restart_remain_live(monkeypatch, tmp_path):
    source = _Source(400)
    module = _module(monkeypatch, tmp_path, source)
    ticks = []

    def tick(_seconds):
        ticks.append(module._current_record_id())
        if module._current_record_id() == 400:
            module._stop.set()

    monkeypatch.setattr(module, "sleep", tick)
    assert module._try_evtlog_mode()
    assert ticks == [256, 400]
    assert module._continuity_gaps == 0 and module.health == 100
    restarted = _module(monkeypatch, tmp_path, source)
    monkeypatch.setattr(restarted, "sleep", lambda _seconds: restarted._stop.set())
    assert restarted._try_evtlog_mode()
    assert restarted._current_record_id() == 400
    assert restarted._continuity_gaps == 0 and restarted.health == 100


def test_page_terminal_replacement_is_rejected_before_staging(monkeypatch, tmp_path):
    source = _Source(2)
    module = _module(monkeypatch, tmp_path, source)
    module._checkpoints[defender._DEFENDER_CHANNEL] = ChannelCheckpoint(
        1, module._record_digest(source.records[1]))

    def replace_terminal():
        source.records[2] = _record(2, "replacement")

    source.after_read = replace_terminal
    with pytest.raises(defender._DefenderGenerationChanged, match="terminal anchor"):
        module._read_native_page(source, 1)
    assert module._current_record_id() == 1


def test_unavailable_anchor_is_retryable_without_advancing_cursor(monkeypatch, tmp_path):
    source = _Source(2)
    module = _module(monkeypatch, tmp_path, source)
    module._checkpoints[defender._DEFENDER_CHANNEL] = ChannelCheckpoint(
        1, module._record_digest(source.records[1]))
    original = source.record_at

    def unavailable(_number):
        raise OSError("inert transient channel access failure")

    monkeypatch.setattr(source, "record_at", unavailable)
    with pytest.raises(OSError, match="transient"):
        module._read_native_page(source, 1)
    assert module._current_record_id() == 1 and not module._startup_blocked
    monkeypatch.setattr(source, "record_at", original)
    assert [record.RecordNumber for record in module._read_native_page(source, 1)] == [2]
