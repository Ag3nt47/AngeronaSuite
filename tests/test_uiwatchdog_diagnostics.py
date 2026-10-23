from __future__ import annotations

from angerona.core import uiwatchdog


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


def test_delay_reports_sample_context_without_asserting_blocker(tmp_path):
    watchdog = uiwatchdog.UiWatchdog(tmp_path / "not_responding.log")
    assert watchdog._dump(5.6, expected_beat=watchdog._last_beat) is True
    report = watchdog.log_path.read_text(encoding="utf-8")
    assert "UI NOT RESPONDING" in report
    assert "heartbeat delayed ~5.6s" in report
    assert "Sampled MainThread stack" in report
    assert "not identify the blocking call" in report
    assert "is the call that is blocking" not in report
    assert "Other live threads" in report


def test_failed_dump_retries_and_success_deduplicates(tmp_path, monkeypatch):
    watchdog = uiwatchdog.UiWatchdog(tmp_path / "not_responding.log")
    watchdog._last_beat = 90.0
    monkeypatch.setattr(uiwatchdog.time, "monotonic", lambda: 100.0)
    attempts = []

    class StopAfterThreeChecks:
        checks = 0

        def wait(self, _timeout):
            self.checks += 1
            return self.checks > 3

    def dump(age, *, expected_beat):
        attempts.append((age, expected_beat))
        return len(attempts) > 1

    watchdog._stop = StopAfterThreeChecks()
    monkeypatch.setattr(watchdog, "_dump", dump)
    watchdog._run()
    assert attempts == [(10.0, 90.0), (10.0, 90.0)]
    assert watchdog._logged_for == 90.0
    assert watchdog._last_dump_at == 100.0


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
