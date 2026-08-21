from __future__ import annotations

import dataclasses
import json
import threading
import time

from angerona.core import storage
from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.storage import FlightRecorder
from angerona.resilience.supervisor import cached_cmdline_probe


def _recorder(tmp_path, monkeypatch) -> FlightRecorder:
    authority = BusAuthority(b"cycle19-performance-authority"[:32])
    monkeypatch.setattr(
        storage.BusAuthority,
        "load",
        classmethod(lambda cls: authority),
    )
    return FlightRecorder(tmp_path / "events.db")


def _signed(authority: BusAuthority, message: str) -> Event:
    event = Event("cycle19", message, Severity.HIGH, details={"source": "test"})
    return dataclasses.replace(event, hmac_sig=authority.sign(event))


def test_heartbeatless_process_probe_scans_once_then_tracks_cached_identity() -> None:
    class FakeProcess:
        def __init__(self, command: list[str]) -> None:
            self.info = {"cmdline": command}
            self.alive = True
            self.identity_checks = 0

        def is_running(self) -> bool:
            self.identity_checks += 1
            return self.alive

    class FakePsutil:
        def __init__(self, processes: list[FakeProcess]) -> None:
            self.processes = processes
            self.table_scans = 0

        def process_iter(self, _attrs):
            self.table_scans += 1
            return list(self.processes)

    blackbox = FakeProcess(["pythonw.exe", "blackbox_recorder.py"])
    psutil = FakePsutil([blackbox])
    probe = cached_cmdline_probe(
        "blackbox_recorder.py", psutil_module=psutil
    )

    assert probe()
    for _tick in range(100):
        assert probe()

    # Previously both supervisors repeated process_iter(cmdline) every tick.
    # The cached Process identity makes 101 healthy checks require one scan.
    assert psutil.table_scans == 1
    assert blackbox.identity_checks == 100

    blackbox.alive = False
    psutil.processes.clear()
    assert not probe()
    assert psutil.table_scans == 2


def test_cached_process_probe_does_not_adopt_a_partial_command_match() -> None:
    class FakeProcess:
        alive = True

        def __init__(self, command: list[str]) -> None:
            self.info = {"cmdline": command}

        def is_running(self) -> bool:
            return self.alive

    class FakePsutil:
        def __init__(self) -> None:
            self.table_scans = 0
            self.processes = [
                FakeProcess(["python", "blackbox_recorder.py", "--unrelated"]),
                FakeProcess(["python", "status_ui", "watchdog"]),
            ]

        def process_iter(self, _attrs):
            self.table_scans += 1
            return list(self.processes)

    psutil = FakePsutil()
    probe = cached_cmdline_probe(
        "status_ui", "scanner", psutil_module=psutil
    )

    assert not probe()
    assert psutil.table_scans == 1


def test_dlq_replay_is_authenticated_idempotent_and_reclaims_spool(
    tmp_path, monkeypatch,
) -> None:
    recorder = _recorder(tmp_path, monkeypatch)
    events = [_signed(recorder.authority, f"event-{index}") for index in range(5)]
    try:
        assert recorder._route_batch_to_dlq(events) == len(events)
        first = recorder.replay_dlq(max_segments=2)
        assert first.inserted == 5
        assert first.duplicates == 0
        assert first.quarantined == 0
        assert first.failures == 0
        assert {event.message for event in recorder.recent(10)} == {
            event.message for event in events
        }
        assert recorder.dlq_status()["bytes"] == 0

        # Re-spooling the exact signed records models a crash/retry duplicate.
        # The replay path recognizes existing authenticated rows and does not
        # insert another copy.
        assert recorder._route_batch_to_dlq(events) == len(events)
        second = recorder.replay_dlq(max_segments=2)
        assert second.inserted == 0
        assert second.duplicates == 5
        assert len(recorder.recent(10)) == 5
        assert recorder.dlq_status()["bytes"] == 0
    finally:
        recorder.close()


def test_dlq_replay_quarantines_forged_raw_line_without_rendering_it(
    tmp_path, monkeypatch,
) -> None:
    recorder = _recorder(tmp_path, monkeypatch)
    signed = _signed(recorder.authority, "trusted")
    payload = json.loads(recorder._dlq_entry(signed, time.time()))
    payload["message"] = "forged after signing"
    active = tmp_path / "dlq_events.json"
    active.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    try:
        result = recorder.replay_dlq(max_segments=1)
        assert result.inserted == 0
        assert result.quarantined == 1
        assert result.segments_completed == 1
        assert result.failures == 0
        assert recorder.recent(10) == []
        status = recorder.dlq_status()
        assert status["quarantine_segments"] == 1
        assert status["quarantine_bytes"] > 0
        quarantine = next(tmp_path.glob("dlq-quarantine-*.ndjson"))
        assert "forged after signing" in quarantine.read_text(encoding="utf-8")
    finally:
        recorder.close()


def test_dlq_hard_segment_cap_assists_replay_without_writer_deadlock(
    tmp_path, monkeypatch,
) -> None:
    recorder = _recorder(tmp_path, monkeypatch)
    monkeypatch.setattr(recorder, "DLQ_SEGMENT_BYTES", 128)
    monkeypatch.setattr(recorder, "DLQ_MAX_SEGMENTS", 1)
    monkeypatch.setattr(recorder, "DLQ_MAX_BYTES", 4096)
    first = _signed(recorder.authority, "first")
    second = _signed(recorder.authority, "second")
    try:
        assert recorder._route_to_dlq(first)
        assert recorder.dlq_status()["segments"] == 1
        result: list[bool] = []
        writer = threading.Thread(
            target=lambda: result.append(recorder._route_to_dlq(second)),
            daemon=True,
        )
        writer.start()
        writer.join(2.0)
        assert not writer.is_alive(), "capacity-assisted replay deadlocked"
        assert result == [True]
        status = recorder.dlq_status()
        assert status["segments"] <= status["max_segments"] == 1
        assert status["bytes"] <= status["max_bytes"]
        assert status["capacity_waits"] >= 1

        replayed = recorder.replay_dlq(max_segments=1)
        assert replayed.inserted == 1
        assert {event.message for event in recorder.recent(10)} == {
            "first", "second"
        }
    finally:
        recorder.close()


def test_dlq_replay_storage_fault_retains_source_for_later_retry(
    tmp_path, monkeypatch,
) -> None:
    recorder = _recorder(tmp_path, monkeypatch)
    event = _signed(recorder.authority, "retry-after-storage-fault")
    assert recorder._route_to_dlq(event)
    real_db = recorder._db

    class FailedDatabase:
        @staticmethod
        def execute(*_args, **_kwargs):
            raise storage.sqlite3.OperationalError("database unavailable")

        @staticmethod
        def rollback():
            return None

    try:
        recorder._db = FailedDatabase()
        failed = recorder.replay_dlq(max_segments=1)
        assert failed.inserted == 0
        assert failed.failures == 1
        assert recorder.dlq_status()["bytes"] > 0

        recorder._db = real_db
        recovered = recorder.replay_dlq(max_segments=1)
        assert recovered.inserted == 1
        assert recovered.failures == 0
        assert recorder.dlq_status()["bytes"] == 0
        assert recorder.recent(1)[0].message == event.message
    finally:
        recorder._db = real_db
        recorder.close()
