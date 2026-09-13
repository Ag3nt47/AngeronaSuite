import os
import time

import psutil
import pytest

import blackbox_recorder as blackbox


def report():
    return {
        "enabled": True, "worker_alive": True,
        "components": {
            "status_reporter": {"state": "verifying", "attempts": 1},
            "flight_recorder": {"state": "healthy", "attempts": 0},
        },
    }


def test_reports_requested_repair_without_claiming_it_succeeded():
    text = blackbox.SuiteHealthWorker._recovery_note({"runtime_healer": report()})
    assert "Status reporter: verifying repair (attempts 1/3)" in text
    assert "Event recorder: available" in text


@pytest.mark.parametrize("bad", [[], "healthy", None])
def test_malformed_report_is_unavailable(bad):
    assert blackbox.SuiteHealthWorker._recovery_note({"runtime_healer": bad}) == (
        "No current recovery report"
    )


def test_invalid_component_metadata_and_dead_healer_are_not_healthy():
    data = report()
    data["components"]["status_reporter"]["state"] = "<img src=secret>"
    assert "invalid" in blackbox.SuiteHealthWorker._recovery_note({"runtime_healer": data})
    data = report()
    data["worker_alive"] = False
    assert "unavailable" in blackbox.SuiteHealthWorker._recovery_note({"runtime_healer": data})


def test_stale_snapshot_does_not_display_current_recovery(monkeypatch):
    process = psutil.Process()
    snapshot = {
        "pid": os.getpid(), "process_started_at": process.create_time(),
        "generated_ts": time.time(), "heartbeat_interval_s": 30,
        "event_bus": {"delivery_mode": "inline", "revision": 0,
                      "subscriber_count": 0, "deliveries": 0,
                      "failures": 0, "budget_violations": 0},
        "runtime_healer": report(),
    }
    monkeypatch.setattr(blackbox, "find_angerona_pid", os.getpid)
    worker = blackbox.SuiteHealthWorker()
    monkeypatch.setattr(worker, "_read_status", lambda: snapshot)
    monkeypatch.setattr(worker, "_failed_modules", lambda _snapshot: [])
    assert "verifying repair" in worker._collect()["recovery_note"]
    snapshot["generated_ts"] -= 600
    assert worker._collect()["recovery_note"] == "No current recovery report"
