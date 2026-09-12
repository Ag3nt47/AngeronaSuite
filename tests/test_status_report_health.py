from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from angerona.core import status_report
from angerona.core.eventbus import Event, EventBus


def _reporter(tmp_path, *, chill=False):
    return status_report.StatusReporter(
        EventBus(),
        SimpleNamespace(count_since=lambda _since: 0),
        SimpleNamespace(modules={}, is_enabled=lambda _name: False),
        SimpleNamespace(
            data_dir=tmp_path, runtime_chill_active=chill,
            ollama_host="local", ollama_model="test",
        ),
    )


def test_snapshot_identifies_process_and_reports_actual_callback_failures(tmp_path):
    reporter = _reporter(tmp_path)
    received = []

    def broken(_event):
        raise RuntimeError("fixture callback failure")

    reporter.bus.subscribe(broken)
    reporter.bus.subscribe(received.append)
    reporter.bus.publish(Event("fixture", "still delivered"))
    snapshot = reporter._snapshot()

    assert snapshot["pid"] == os.getpid()
    assert snapshot["process_started_at"] <= snapshot["generated_ts"]
    assert snapshot["heartbeat_interval_s"] == 30
    assert snapshot["event_bus"] == {
        "delivery_mode": "inline", "revision": 1, "subscriber_count": 2,
        "deliveries": 2, "failures": 1,
        "budget_violations": sum(row.budget_violations for row in reporter.bus.subscriber_metrics()),
    }
    assert received[0].message == "still delivered"


@pytest.mark.parametrize("chill,heartbeat", [(False, 30), (True, 60)])
def test_quiet_snapshot_keeps_bounded_heartbeat_and_refreshes_timestamp(
    tmp_path, monkeypatch, chill, heartbeat,
):
    reporter = _reporter(tmp_path, chill=chill)
    now = [1000.0]
    monkeypatch.setattr(status_report.time, "time", lambda: now[0])
    monkeypatch.setattr(status_report.time, "monotonic", lambda: now[0])
    reporter._write()
    path = tmp_path / "diagnostics" / "status.json"
    first = path.read_bytes()
    assert json.loads(first)["heartbeat_interval_s"] == heartbeat
    now[0] += heartbeat - 1
    reporter._write()
    assert path.read_bytes() == first
    now[0] += 1
    reporter._write()
    latest = json.loads(path.read_bytes())
    assert latest["generated_ts"] == now[0]
    assert latest["event_bus"]["revision"] == 0


def test_changed_bus_counters_persist_before_quiet_heartbeat(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    now = [1000.0]
    monkeypatch.setattr(status_report.time, "monotonic", lambda: now[0])
    reporter._write()
    now[0] += 3
    reporter.bus.publish(Event("fixture", "new activity"))
    reporter._write()
    data = json.loads((tmp_path / "diagnostics" / "status.json").read_text())
    assert data["event_bus"]["revision"] == 1


def test_reader_sees_complete_previous_snapshot_until_atomic_replace(tmp_path, monkeypatch):
    path = tmp_path / "status.json"
    path.write_text('{"revision": 1}')
    replacements = []

    def replace(source, destination):
        assert json.loads(destination.read_text()) == {"revision": 1}
        assert json.loads(source.read_text()) == {"revision": 2}
        replacements.append(destination)
        os.replace(source, destination)

    monkeypatch.setattr(status_report, "replace_with_retry", replace)
    status_report.StatusReporter._atomic_write(path, '{"revision": 2}')
    assert replacements == [path]
    assert json.loads(path.read_text()) == {"revision": 2}
    assert list(tmp_path.glob("*.tmp")) == []


def test_failed_replace_preserves_previous_snapshot_and_retries(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    reporter._write()
    path = tmp_path / "diagnostics" / "status.json"
    previous = path.read_bytes()
    persisted_at = reporter._last_persisted_at
    original_replace = status_report.replace_with_retry

    def blocked(_source, _destination):
        raise PermissionError("fixture sharing failure")

    monkeypatch.setattr(status_report, "replace_with_retry", blocked)
    reporter.bus.publish(Event("fixture", "new activity"))
    reporter._write()
    assert path.read_bytes() == previous
    assert reporter._last_persisted_at == persisted_at
    assert list(path.parent.glob("*.tmp")) == []
    monkeypatch.setattr(status_report, "replace_with_retry", original_replace)
    reporter._write()
    assert json.loads(path.read_bytes())["event_bus"]["revision"] == 1


def test_blackbox_reads_real_reporter_across_chill_and_event_delivery(tmp_path, monkeypatch):
    import blackbox_recorder as blackbox

    reporter = _reporter(tmp_path, chill=True)
    reporter._write()
    path = tmp_path / "diagnostics" / "status.json"
    snapshot = json.loads(path.read_bytes())
    monkeypatch.setattr(blackbox, "STATUS_JSON", path)
    monkeypatch.setattr(blackbox, "DATA_STATUS_JSON", path)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", tmp_path / "absent-selftests.json")
    monkeypatch.setattr(blackbox, "find_angerona_pid", os.getpid)
    now = [snapshot["generated_ts"] + 45]
    monkeypatch.setattr(blackbox.time, "time", lambda: now[0])
    worker = blackbox.SuiteHealthWorker()

    initial = worker._collect()
    assert initial["state"] == "RUNNING"
    assert initial["bus_state"] == "OBSERVED"
    assert initial["bus_fresh"] is True
    now[0] += 15
    reporter._write(force=True)
    assert worker._collect()["bus_state"] == "QUIET"
    now[0] += 60
    reporter.bus.publish(Event("fixture", "new event"))
    reporter._write(force=True)
    active = worker._collect()
    assert active["bus_state"] == "ACTIVE"
    assert active["bus_warnings"] == []
    now[0] += 150
    stale = worker._collect()
    assert stale["state"] == "RUNNING"
    assert stale["bus_state"] == "STALE"
