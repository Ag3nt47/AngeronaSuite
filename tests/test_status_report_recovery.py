from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import status_report
from angerona.core.eventbus import EventBus


def _reporter(tmp_path, *, interval=300.0):
    return status_report.StatusReporter(
        EventBus(),
        SimpleNamespace(count_since=lambda _since: 0),
        SimpleNamespace(modules={}, is_enabled=lambda _name: False),
        SimpleNamespace(
            data_dir=tmp_path, runtime_chill_active=False,
            ollama_host="local", ollama_model="test",
        ),
        interval=interval,
    )


def _await(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "reporter did not reach the expected state"


def test_missing_diagnostics_directory_recovers_on_worker(tmp_path):
    reporter = _reporter(tmp_path)
    reporter.start()
    try:
        _await(lambda: reporter.recovery_snapshot()["healthy"])
        directory = tmp_path / "diagnostics"
        for path in directory.iterdir():
            path.unlink()
        directory.rmdir()
        assert reporter.recover()
        _await(lambda: (directory / "status.txt").is_file())
        assert json.loads((directory / "status.json").read_text())["event_bus"]
        assert reporter.recovery_snapshot()["healthy"]
    finally:
        reporter.stop()


def test_constructor_directory_failure_retains_recoverable_destination(tmp_path, monkeypatch):
    original_mkdir = Path.mkdir

    def blocked(path, *args, **kwargs):
        if path == tmp_path / "diagnostics":
            raise PermissionError("secret fixture location")
        return original_mkdir(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "mkdir", blocked)
        reporter = _reporter(tmp_path)
    initial = reporter.recovery_snapshot()
    assert initial["last_success_age_seconds"] is None
    assert initial["write_failures"] == 1
    assert initial["last_error_type"] == "PermissionError"
    assert not initial["healthy"]
    try:
        assert reporter.recover()
        _await(lambda: reporter.recovery_snapshot()["healthy"])
        assert (tmp_path / "diagnostics" / "status.txt").is_file()
        assert reporter.recovery_snapshot()["write_failures"] == 1
        assert reporter.recovery_snapshot()["last_error_type"] == ""
    finally:
        reporter.stop()


def test_concurrent_start_and_recover_keep_one_worker(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    entered = []
    original_loop = reporter._loop

    def observed_loop():
        entered.append(threading.get_ident())
        original_loop()

    monkeypatch.setattr(reporter, "_loop", observed_loop)
    starters = [threading.Thread(target=reporter.start) for _ in range(8)]
    try:
        for starter in starters:
            starter.start()
        for starter in starters:
            starter.join()
        for _ in range(8):
            assert reporter.recover()
        _await(lambda: reporter.recovery_snapshot()["healthy"])
        assert entered == [reporter._thread.ident]
    finally:
        reporter.stop()


def test_stopped_reporter_rejects_recovery_but_explicit_start_works(tmp_path):
    reporter = _reporter(tmp_path)
    reporter.start()
    _await(lambda: reporter.recovery_snapshot()["healthy"])
    first_worker = reporter._thread
    reporter.stop()
    assert not reporter.recover()
    assert reporter._thread is first_worker
    stopped = reporter.recovery_snapshot()
    assert stopped["stopping"] and not stopped["worker_alive"]
    assert not stopped["healthy"]
    try:
        reporter.start()
        _await(lambda: reporter.recovery_snapshot()["healthy"])
        assert reporter._thread is not first_worker
    finally:
        reporter.stop()


def test_recover_restarts_dead_worker(tmp_path):
    reporter = _reporter(tmp_path)
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    reporter._thread = dead
    try:
        assert reporter.recover()
        _await(lambda: reporter.recovery_snapshot()["healthy"])
        assert reporter._thread is not dead
    finally:
        reporter.stop()


def test_worker_start_failure_does_not_leave_an_unjoinable_thread(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)

    def fail(_worker):
        raise RuntimeError("thread creation failed")

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", fail)
        with pytest.raises(RuntimeError):
            reporter.recover()
    assert reporter._thread is None
    reporter.stop()
    assert not reporter.recover()


def test_recovery_during_shutdown_cannot_revive_worker(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    reporter.start()
    _await(lambda: reporter.recovery_snapshot()["healthy"])
    final_write_entered = threading.Event()
    release_final_write = threading.Event()

    def final_write(*, force=False):
        final_write_entered.set()
        assert release_final_write.wait(3.0)

    monkeypatch.setattr(reporter, "_write", final_write)
    shutdown = threading.Thread(target=reporter.stop)
    shutdown.start()
    try:
        assert final_write_entered.wait(3.0)
        assert not reporter.recover()
        assert not reporter.recovery_snapshot()["worker_alive"]
    finally:
        release_final_write.set()
        shutdown.join(timeout=3.0)
    assert not shutdown.is_alive()


def test_forced_refresh_runs_only_on_existing_worker(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    completed = threading.Event()
    writers = []
    original_write = reporter._atomic_write

    def observed_write(path, content):
        writers.append(threading.get_ident())
        original_write(path, content)
        if path.name == "status.txt":
            completed.set()

    monkeypatch.setattr(reporter, "_atomic_write", observed_write)
    try:
        reporter.start()
        assert completed.wait(3.0)
        completed.clear()
        first_count = len(writers)
        assert reporter.recover()
        assert completed.wait(3.0)
        assert len(writers) == first_count + 2
        assert set(writers) == {reporter._thread.ident}
        assert threading.get_ident() not in writers
    finally:
        reporter.stop()


def test_failed_writes_keep_previous_success_and_redact_exception(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    assert reporter._write(force=True)
    previous = (tmp_path / "diagnostics" / "status.json").read_bytes()
    last_success = reporter._last_success_at

    def blocked(_path, _content):
        raise PermissionError("SECRET / credential / private-path")

    monkeypatch.setattr(reporter, "_atomic_write", blocked)
    assert reporter._write(force=True) is False
    health = reporter.recovery_snapshot()
    assert health["write_failures"] == 1
    assert health["last_error_type"] == "PermissionError"
    assert "SECRET" not in json.dumps(health)
    assert reporter._last_success_at == last_success
    assert (tmp_path / "diagnostics" / "status.json").read_bytes() == previous


def test_loop_records_unexpected_error_and_bounds_recovery_retries(tmp_path, monkeypatch):
    reporter = _reporter(tmp_path)
    attempts = []

    def failed_write(*, force=False):
        attempts.append(force)
        raise RuntimeError("SECRET unexpected failure")

    monkeypatch.setattr(reporter, "_write", failed_write)
    monkeypatch.setattr(reporter, "_effective_interval", lambda: 1.0)
    try:
        reporter.start()
        _await(lambda: reporter.recovery_snapshot()["write_failures"] == 1)
        for _ in range(100):
            reporter.recover()
        time.sleep(0.05)
        assert attempts == [True]
        health = reporter.recovery_snapshot()
        assert health["last_error_type"] == "RuntimeError"
        assert health["last_success_age_seconds"] is None
        assert "SECRET" not in json.dumps(health)
        assert not health["healthy"]
    finally:
        reporter.stop()


@pytest.mark.parametrize("age,interval,healthy", [(119, 3, True), (121, 3, False), (179, 60, True), (181, 60, False)])
def test_health_requires_recent_actual_write(tmp_path, monkeypatch, age, interval, healthy):
    reporter = _reporter(tmp_path, interval=interval)
    reporter._thread = SimpleNamespace(is_alive=lambda: True)
    reporter._last_success_at = 1000.0
    monkeypatch.setattr(status_report.time, "monotonic", lambda: 1000.0 + age)
    snapshot = reporter.recovery_snapshot()
    assert snapshot["last_success_age_seconds"] == age
    assert snapshot["healthy"] is healthy


def test_directory_symlink_is_rejected_without_writing_target(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    link = tmp_path / "diagnostics"
    try:
        link.symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks unavailable")
    reporter = _reporter(tmp_path)
    assert reporter._write(force=True) is False
    assert list(external.iterdir()) == []
    assert reporter.recovery_snapshot()["last_success_age_seconds"] is None


def test_reparse_attribute_is_rejected_before_creation(tmp_path, monkeypatch):
    original_lstat = Path.lstat

    def reparse(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        if path == tmp_path:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x400)
        return metadata

    monkeypatch.setattr(Path, "lstat", reparse)
    reporter = _reporter(tmp_path)
    assert reporter._write(force=True) is False
    assert not (tmp_path / "diagnostics").exists()
    assert reporter.recovery_snapshot()["last_error_type"] == "OSError"


def test_hardlinked_destination_is_rejected_without_altering_either_file(tmp_path):
    reporter = _reporter(tmp_path)
    original = tmp_path / "original.json"
    original.write_text("unchanged evidence", encoding="utf-8")
    destination = tmp_path / "diagnostics" / "status.json"
    destination.hardlink_to(original)
    assert reporter._write(force=True) is False
    assert destination.read_text() == "unchanged evidence"
    assert original.read_text() == "unchanged evidence"
    assert reporter.recovery_snapshot()["last_success_age_seconds"] is None


def test_healing_evidence_appears_in_json_and_readable_text(tmp_path):
    reporter = _reporter(tmp_path)
    evidence = {
        "enabled": True, "worker_alive": True,
        "components": {"status_reporter": {"state": "healthy", "attempts": 1, "last_result": "recovered"}},
    }
    reporter.runtime_healer = SimpleNamespace(snapshot=lambda: evidence)
    assert reporter._write(force=True)
    snapshot = json.loads((tmp_path / "diagnostics" / "status.json").read_text())
    assert snapshot["runtime_healer"] == evidence
    assert "status_reporter: healthy / attempts=1 / last result=recovered" in (
        tmp_path / "diagnostics" / "status.txt"
    ).read_text(encoding="utf-8")
