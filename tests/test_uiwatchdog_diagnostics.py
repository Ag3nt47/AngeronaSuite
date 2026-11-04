from __future__ import annotations

import os
import threading

from angerona.core import startup_diagnostics, uiwatchdog


def test_recovered_heartbeat_is_not_reported_as_current_stall(tmp_path, monkeypatch):
    watchdog = uiwatchdog.UiWatchdog(tmp_path / "not_responding.log")
    watchdog._last_beat = 1.0
    monkeypatch.setattr(uiwatchdog.time, "monotonic", lambda: 10.0)

    def recovered_frames():
        watchdog.beat()
        return {}

    monkeypatch.setattr(uiwatchdog.sys, "_current_frames", recovered_frames)
    assert watchdog._dump(9.0, expected_beat=1.0) is False
    assert not watchdog.log_path.exists()


def test_delay_reports_sample_context_without_asserting_blocker(tmp_path, monkeypatch):
    watchdog = uiwatchdog.UiWatchdog(tmp_path / "not_responding.log")
    calls = []

    def identity():
        calls.append(None)
        return {"pid": os.getpid(), "birth_filetime": "132537600123456789"}

    monkeypatch.setattr(startup_diagnostics, "process_identity", identity)
    assert watchdog._dump(5.6, expected_beat=watchdog._last_beat, watchdog_sample_gap=1.25) is True
    assert watchdog._dump(7.0) is True
    assert calls == [None]
    report = watchdog.log_path.read_text(encoding="utf-8")
    assert "UI NOT RESPONDING" in report
    assert "heartbeat delayed ~5.6s" in report
    assert f"pid={os.getpid()} birth_filetime=132537600123456789" in report
    assert f"main_native_tid={threading.main_thread().native_id}" in report
    assert "watchdog_sample_gap_s=1.250" in report
    assert "watchdog_sample_gap_s=unavailable" in report
    assert "Sampled MainThread stack" in report
    assert "not identify the blocking call" in report
    assert "is the call that is blocking" not in report
    assert "Other live threads" in report


def test_failed_dump_retries_and_success_deduplicates(tmp_path, monkeypatch):
    watchdog = uiwatchdog.UiWatchdog(tmp_path / "not_responding.log")
    watchdog._last_beat = 90.0
    clock = iter([94.0, 100.0, 102.5, 103.5])
    monkeypatch.setattr(uiwatchdog.time, "monotonic", lambda: next(clock))
    attempts = []

    class StopAfterFourChecks:
        checks = 0

        def wait(self, _timeout):
            self.checks += 1
            return self.checks > 4

    def dump(age, *, expected_beat, watchdog_sample_gap):
        attempts.append((age, expected_beat, watchdog_sample_gap))
        return len(attempts) > 1

    watchdog._stop = StopAfterFourChecks()
    monkeypatch.setattr(watchdog, "_dump", dump)
    watchdog._run()
    assert attempts == [(10.0, 90.0, 6.0), (12.5, 90.0, 2.5)]
    assert watchdog._logged_for == 90.0
    assert watchdog._last_dump_at == 102.5


def test_unavailable_native_birth_preserves_the_watchdog_report(tmp_path, monkeypatch):
    watchdog = uiwatchdog.UiWatchdog(tmp_path / "not_responding.log")

    def unavailable():
        raise OSError("native birth unavailable")

    monkeypatch.setattr(startup_diagnostics, "process_identity", unavailable)
    assert watchdog._dump(8.0) is True
    report = watchdog.log_path.read_text(encoding="utf-8")
    assert f"pid={os.getpid()} birth_filetime=unavailable" in report
    assert "watchdog_sample_gap_s=unavailable" in report
    assert "heartbeat delayed ~8.0s" in report


def test_blackbox_separates_delayed_heartbeat_from_lock_diagnostic():
    import blackbox_recorder as blackbox

    delayed = blackbox.plain_english_for(
        "UI NOT RESPONDING — GUI heartbeat delayed ~5.6s\n"
        "Sampled MainThread stack: qt.exec()"
    )
    assert len(delayed) == 1
    assert "does not prove a deadlock" in delayed[0]
    locked = blackbox.plain_english_for("Thread Worker blocked: acquire Lock")
    assert len(locked) == 1
    assert "Compare multiple thread samples" in locked[0]
