import os
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import blackbox_recorder as blackbox


def test_blackbox_accepts_both_selftest_report_shapes() -> None:
    rows = [{"module": "Scanner", "detail": "failed"}]

    assert blackbox._selftest_failures(rows) == rows
    assert blackbox._selftest_failures({"failures": rows}) == rows
    assert blackbox._selftest_failures({"failures": "invalid"}) == []
    assert blackbox._selftest_failures({"failures": None}) == []
    assert blackbox._selftest_failures(None) == []


@pytest.mark.parametrize("profile", ["override", "source", "elevated", "frozen"])
def test_data_root_uses_shared_policy_without_creating_state(monkeypatch, tmp_path, profile):
    from angerona.core import data_paths

    expected = tmp_path / profile
    monkeypatch.delenv("ANGERONA_DATA", raising=False)
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setattr(data_paths.sys, "frozen", profile == "frozen", raising=False)
    monkeypatch.setattr(data_paths, "_elevated_source_runtime", lambda: profile == "elevated")
    monkeypatch.setattr(data_paths, "_windows_source_data_root", lambda: expected)
    monkeypatch.setattr(data_paths, "_canonical_source_data_root", lambda: expected)
    monkeypatch.setattr(data_paths, "_frozen_default_data_root", lambda: expected)
    if profile == "override":
        monkeypatch.setenv("ANGERONA_DATA", str(expected))

    def forbidden(*args, **kwargs):
        pytest.fail("Black Box must not create or harden suite state")

    monkeypatch.setattr(data_paths, "_create_admin_directory_atomic", forbidden)
    monkeypatch.setattr(data_paths, "_verify_protected_source_data_root", forbidden)
    monkeypatch.setattr(data_paths, "_harden_frozen_data_root", forbidden)
    data_paths._canonical_data_path.cache_clear()
    assert blackbox._angerona_data_dir() == expected.resolve()
    assert not expected.exists()


def test_standalone_source_resolution_adds_source_import_path(monkeypatch, tmp_path):
    from angerona.core import data_paths

    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.setattr(blackbox, "APP_DIR", tmp_path)
    monkeypatch.setattr(blackbox.sys, "path", list(blackbox.sys.path))
    calls = []
    monkeypatch.setattr(data_paths, "data_dir", lambda *, create: calls.append(create) or tmp_path)
    assert blackbox._angerona_data_dir() == tmp_path
    assert str(source) in blackbox.sys.path
    assert calls == [False]


@pytest.mark.parametrize("name,cmdline,expected", [
    ("python.exe", ["python.exe", "-m", "angerona"], True),
    ("pythonw.exe", ["pythonw.exe", "-u", "-X", "utf8", "-m", "angerona", "--tray"], True),
    ("python3.13", ["python3.13", "-m", "angerona"], True),
    ("Angerona.exe", [], True),
    ("AngeronaBlackBox.exe", [r"D:\Angerona\AngeronaBlackBox.exe"], False),
    ("python.exe", [r"D:\AngeronaSuite\venv\python.exe", "-m", "pytest"], False),
    ("python.exe", ["python.exe", r"D:\AngeronaSuite\blackbox_recorder.py"], False),
    ("python.exe", ["python.exe", "tools/selfcheck.py", "-m", "angerona"], False),
    ("python.exe", ["python.exe", "-c", "print('-m angerona')"], False),
    ("python.exe", ["python.exe", "-m", "angerona.core.helper"], False),
    ("my-python-helper.exe", ["helper", "-m", "angerona"], False),
])
def test_core_process_matching_uses_entry_point(name, cmdline, expected):
    assert blackbox._is_angerona_core(name, cmdline) is expected


def test_pid_discovery_ignores_large_helpers_and_prefers_matching_core_child(monkeypatch):
    def proc(pid, ppid, module, rss):
        return SimpleNamespace(info={"pid": pid, "ppid": ppid, "name": "python.exe",
                                    "cmdline": [r"D:\AngeronaSuite\python.exe", "-m", module],
                                    "memory_info": SimpleNamespace(rss=rss)})

    monkeypatch.setattr(blackbox.psutil, "process_iter", lambda attrs: iter([
        proc(101, 1, "pytest", 10**9), proc(102, 1, "angerona", 10**8),
        proc(103, 102, "angerona", 10**6),
    ]))
    assert blackbox.find_angerona_pid() == 103


def _snapshot(*, generated=970.0, interval=30.0, revision=12, deliveries=24):
    return {"pid": 101, "process_started_at": 500.0, "generated_ts": generated,
            "heartbeat_interval_s": interval,
            "event_bus": {"delivery_mode": "inline", "revision": revision,
                          "subscriber_count": 2, "deliveries": deliveries,
                          "failures": 0, "budget_violations": 0},
            "modules": [], "counts": {}}


@pytest.mark.parametrize("interval,age", [(30, 30), (60, 59), (60, 120)])
def test_health_allows_normal_and_chill_heartbeat_cadence(interval, age):
    worker = blackbox.SuiteHealthWorker()
    health = worker._observe_bus(_snapshot(generated=1000-age, interval=interval), 101, 500, 1000)
    assert health["bus_fresh"] is True
    assert health["bus_state"] == "OBSERVED"


def test_inline_bus_distinguishes_quiet_heartbeats_from_observed_activity():
    worker = blackbox.SuiteHealthWorker()
    first = worker._observe_bus(_snapshot(generated=900), 101, 500, 900)
    quiet = worker._observe_bus(_snapshot(generated=960), 101, 500, 960)
    active_snapshot = _snapshot(generated=990, revision=13, deliveries=26)
    active_snapshot["event_bus"].update(failures=1, budget_violations=3)
    active = worker._observe_bus(active_snapshot, 101, 500, 990)
    repeat = worker._observe_bus(active_snapshot, 101, 500, 993)
    assert first["bus_state"] == "OBSERVED"
    assert quiet["bus_state"] == "QUIET"
    assert active["bus_state"] == repeat["bus_state"] == "ACTIVE"
    assert active["bus_warnings"] == ["1 subscriber failures recorded", "3 delivery budget overruns recorded"]


@pytest.mark.parametrize("update", [
    {"pid": 102}, {"process_started_at": 499}, {"process_started_at": None},
    {"generated_ts": 490}, {"generated_ts": 1100}, {"generated_ts": float("nan")},
    {"heartbeat_interval_s": None}, {"heartbeat_interval_s": "60"},
    {"event_bus": []}, {"event_bus": {"delivery_mode": "queued"}},
])
def test_unrelated_or_malformed_status_never_proves_bus_activity(update):
    snapshot = _snapshot()
    snapshot.update(update)
    result = blackbox.SuiteHealthWorker()._observe_bus(snapshot, 101, 500, 1000)
    assert result["bus_state"] == "UNKNOWN"
    assert result["bus_warnings"] == []


@pytest.fixture
def health_environment(monkeypatch, tmp_path):
    status = tmp_path / "status.json"
    monkeypatch.setattr(blackbox, "STATUS_JSON", status)
    monkeypatch.setattr(blackbox, "DATA_STATUS_JSON", status)
    monkeypatch.setattr(blackbox, "SELFTEST_FAILURES", tmp_path / "selftest.json")
    monkeypatch.setattr(blackbox, "find_angerona_pid", lambda: 101)
    process = SimpleNamespace(oneshot=nullcontext, status=lambda: blackbox.psutil.STATUS_RUNNING,
                              cpu_percent=lambda interval: 0, memory_info=lambda: SimpleNamespace(rss=64),
                              create_time=lambda: 500.0)
    monkeypatch.setattr(blackbox.psutil, "Process", lambda pid: process)
    monkeypatch.setattr(blackbox.time, "time", lambda: 1000.0)
    return status


def test_stale_status_and_fresh_database_do_not_mark_running_process_frozen(monkeypatch, health_environment):
    snapshot = _snapshot(generated=800, interval=60)
    snapshot["modules"] = [{"name": "OldModule", "last_error": "prior failure"}]
    health_environment.write_text(json.dumps(snapshot), encoding="utf-8")
    database = health_environment.with_name("flight-recorder.db")
    database.write_bytes(b"unrelated activity")
    monkeypatch.setattr(blackbox, "FLIGHT_RECORDER", database)
    monkeypatch.setattr(blackbox, "FLOW_METRICS", database)
    monkeypatch.setattr(blackbox, "RINGBUFFER", database)
    health = blackbox.SuiteHealthWorker()._collect()
    assert health["state"] == "RUNNING"
    assert health["bus_state"] == "STALE"
    assert health["bus_fresh"] is False
    assert health["failed"] == []


@pytest.mark.parametrize("raw", ["{", "null", "[]", '{"modules": null}',
                                  '{"counts": [], "modules": [null, 42]}'])
def test_worker_survives_malformed_status_then_recovers(health_environment, raw):
    worker = blackbox.SuiteHealthWorker()
    health_environment.write_text(raw, encoding="utf-8")
    assert worker._collect()["bus_state"] == "UNKNOWN"
    snapshot = _snapshot()
    snapshot.update(modules=[None, {"name": 17, "last_error": {"detail": "failure"}}], counts=[])
    health_environment.write_text(json.dumps(snapshot), encoding="utf-8")
    recovered = worker._collect()
    assert recovered["bus_state"] == "OBSERVED"
    assert recovered["counts"] == {}
    assert recovered["failed"][0]["name"] == "17"
    assert "failure" in recovered["failed"][0]["detail"]


def test_health_ui_renders_quiet_stale_and_cumulative_errors(health_environment):
    worker = blackbox.SuiteHealthWorker()
    snapshot = _snapshot(generated=940)
    health_environment.write_text(json.dumps(snapshot), encoding="utf-8")
    worker._collect()
    snapshot["generated_ts"] = 970
    snapshot["event_bus"]["failures"] = 2
    snapshot["modules"] = [{"name": 17, "last_error": "<b>literal error</b>"}]
    health_environment.write_text(json.dumps(snapshot), encoding="utf-8")
    tab = blackbox.HealthTab()
    try:
        tab.on_health(worker._collect())
        assert tab.state_lbl.text() == "STATE: RUNNING"
        assert "QUIET" in tab.bus_lbl.text()
        assert "2 subscriber failures" in tab.snapshot_text()
        assert "(cumulative)" in tab.bus_lbl.text()
        assert tab.fail_table.item(0, 1).text() == "<b>literal error</b>"
        snapshot["generated_ts"] = 800
        health_environment.write_text(json.dumps(snapshot), encoding="utf-8")
        tab.on_health(worker._collect())
        assert "STALE" in tab.bus_lbl.text()
        assert tab.state_lbl.text() == "STATE: RUNNING"
    finally:
        tab.close()


def test_archive_clear_copies_snapshots_without_moving_live_diagnostics(monkeypatch, tmp_path):
    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir()
    status = diagnostics / "status.json"
    original = json.dumps(_snapshot()).encode()
    status.write_bytes(original)
    huge_log = diagnostics / "crash.log"
    huge_log.write_bytes(b"discarded prefix\n" + b"x" * blackbox.MAX_STATUS_BYTES)
    original_stat = status.stat()
    archive = tmp_path / "archive"
    monkeypatch.setattr(blackbox, "DIAG_DIR", diagnostics)
    monkeypatch.setattr(blackbox, "ARCHIVE_DIR", archive)
    messages = []
    monkeypatch.setattr(blackbox.QMessageBox, "question", lambda *args: blackbox.QMessageBox.Yes)
    monkeypatch.setattr(blackbox.QMessageBox, "information", lambda *args: messages.append(args[-1]))
    cleared = []
    window = SimpleNamespace(tab_logs=SimpleNamespace(console=SimpleNamespace(clear=lambda: cleared.append(True))))

    blackbox.BlackBoxWindow.on_archive_clear(window)

    assert status.read_bytes() == original
    assert status.stat().st_mtime_ns == original_stat.st_mtime_ns
    assert huge_log.exists()
    assert next(archive.glob("*_status.json")).read_bytes() == original
    assert next(archive.glob("*_crash.log.tail")).stat().st_size == blackbox.MAX_STATUS_BYTES
    assert cleared == [True]
    assert messages[0].startswith("Copied 2 diagnostic snapshot(s)")
