from __future__ import annotations

import json
import time

import pytest

from angerona.core.eventbus import Event, EventBus
from angerona.core.module_base import Severity
from angerona.modules import daily_briefing as briefing


class _Recorder:
    def __init__(self, events, total: int | None = None) -> None:
        self.events = list(events)
        self.total = len(self.events) if total is None else total
        self.calls = []

    def bounded_events_in_window(self, start_ts, end_ts, *, limit):
        self.calls.append((start_ts, end_ts, limit))
        return list(self.events), self.total


def _module(tmp_path, monkeypatch, recorder) -> briefing.DailyBriefingModule:
    monkeypatch.setattr(briefing, "_shared_logs", lambda: tmp_path)
    monkeypatch.setattr(briefing, "_read_remediation", lambda: {})
    module = briefing.DailyBriefingModule()
    module._cursor_path_override = tmp_path / "briefing.cursor.json"
    module._cursor_key_override = b"B" * 32
    module.bind_recorder(recorder)
    module.bind(EventBus())
    monkeypatch.setattr(module, "_ask_ollama", lambda facts: None)
    return module


def test_briefing_uses_exact_durable_interval_and_commits_after_artifacts(
    tmp_path, monkeypatch
) -> None:
    now = time.time()
    event = Event("Sensor", "bounded evidence", Severity.HIGH, ts=now - 5)
    recorder = _Recorder([event])
    module = _module(tmp_path, monkeypatch, recorder)

    module._make_briefing()

    assert recorder.calls and recorder.calls[0][2] == briefing._WINDOW_LIMIT
    report = json.loads((tmp_path / "daily_briefing.json").read_text("utf-8"))
    assert report["summary"]["window"]["source"] == "flight-recorder"
    assert report["summary"]["window"]["complete"] is True
    assert report["summary"]["window"]["events_total"] == 1
    assert report["narrative_authority"] == "advisory-only"
    assert (tmp_path / "daily_briefing.txt").is_file()
    assert (tmp_path / "briefing.cursor.json").is_file()
    assert module._count == 1
    assert module._last_coverage_complete is True
    assert any("briefing ready" in event.message.lower() for event in module._bus.recent(10))


def test_bounded_overflow_is_explicit_and_never_complete(tmp_path, monkeypatch) -> None:
    now = time.time()
    recorder = _Recorder(
        [Event("Sensor", "one", Severity.INFO, ts=now - 3)],
        total=25_000,
    )
    module = _module(tmp_path, monkeypatch, recorder)

    summary, _remediation, _incidents = module._gather(now - 100, now)

    assert summary["window"]["complete"] is False
    assert summary["window"]["events_total"] == 25_000
    assert summary["window"]["events_omitted"] == 24_999


def test_persistence_failure_does_not_increment_or_emit_success(
    tmp_path, monkeypatch
) -> None:
    now = time.time()
    module = _module(
        tmp_path,
        monkeypatch,
        _Recorder([Event("Sensor", "one", Severity.INFO, ts=now - 1)]),
    )
    real_write = module._atomic_write

    def fail_json(path, payload):
        if path.name == "daily_briefing.json":
            raise OSError("inert persistence failure")
        return real_write(path, payload)

    monkeypatch.setattr(module, "_atomic_write", fail_json)

    with pytest.raises(OSError):
        module._make_briefing()

    assert module._count == 0
    assert not (tmp_path / "briefing.cursor.json").exists()
    assert not any("briefing ready" in event.message.lower() for event in module._bus.recent(10))


def test_authenticated_cursor_tamper_is_not_reenrolled(tmp_path, monkeypatch) -> None:
    module = _module(tmp_path, monkeypatch, _Recorder([]))
    module._make_briefing()
    path = tmp_path / "briefing.cursor.json"
    document = json.loads(path.read_text("utf-8"))
    document["last_success_ts"] -= 86_400
    path.write_text(json.dumps(document), encoding="utf-8")

    restarted = _module(tmp_path, monkeypatch, _Recorder([]))
    assert restarted._load_cursor() is None
    assert restarted._cursor_status == "invalid"
    with pytest.raises(RuntimeError):
        restarted._make_briefing()
    assert json.loads(path.read_text("utf-8"))["last_success_ts"] == document[
        "last_success_ts"
    ]


def test_eventbus_fallback_declares_unknown_omission(tmp_path, monkeypatch) -> None:
    module = _module(tmp_path, monkeypatch, _Recorder([]))
    module._recorder = None
    module._bus.publish(Event("Sensor", "recent", Severity.INFO, ts=time.time()))

    summary, _remediation, _incidents = module._gather()

    assert summary["window"]["source"] == "eventbus-fallback"
    assert summary["window"]["complete"] is False
    assert summary["window"]["events_omitted"] is None
