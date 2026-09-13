"""Inert Shadow Shield cancellation, real progress and supervisor budgets."""
from __future__ import annotations

import io
import os
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.module_contract import build_capability_contract
from angerona.modules import shadow_shield
from angerona.modules.shadow_shield import ShadowShield
from angerona.modules.watchdog_monitor import WatchdogMonitor


@pytest.fixture
def shield(tmp_path, monkeypatch):
    module = ShadowShield()
    module._cache_dir = tmp_path / "cache"
    module.emit = lambda *_args, **_kwargs: None
    monkeypatch.setattr(shadow_shield.subprocess, "Popen", lambda *_a, **_k: pytest.fail("live subprocess forbidden"))
    return module


class _Process:
    returncode = 0

    def __init__(self):
        self.killed = 0
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def kill(self):
        self.killed += 1

    def communicate(self, *, timeout):
        return "synthetic-shadow-id", ""


def test_stop_after_file_walk_prevents_vss_and_does_not_attest_a_cycle(shield, monkeypatch):
    def files():
        shield.stop()
        yield from ()

    monkeypatch.setattr(shield, "_protected_files", files)
    shield.run()
    assert shield._snapshots == 0
    assert shield._last_vss == 0
    assert not shield.first_cycle_complete
    assert "initial coverage is incomplete" in shield.health_note


def test_stopped_generation_never_launches_vss(shield):
    shield.stop()
    assert shield._take_vss_snapshot() is None
    assert shield._last_vss == 0


def test_vss_stop_cancels_only_own_child_without_late_health(shield, monkeypatch):
    process = _Process()
    calls = []

    def communicate(*, timeout):
        calls.append(timeout)
        if not process.killed:
            shield.stop()
            raise subprocess.TimeoutExpired("synthetic", timeout)
        return "", ""

    process.communicate = communicate
    monkeypatch.setattr(shadow_shield.subprocess, "Popen", lambda *_a, **_k: process)
    shield.set_health(42, "existing coverage")
    assert shield._take_vss_snapshot() is None
    assert process.killed == 1
    assert calls == [0.25, 1.0]
    assert shield._snapshots == 0
    assert shield.health == 42
    assert shield.health_note == "existing coverage"


@pytest.mark.parametrize("replacement", [False, True])
def test_late_vss_success_cannot_publish_for_stopped_or_replaced_generation(shield, monkeypatch, replacement):
    process = _Process()

    def communicate(*, timeout):
        if replacement:
            shield._stop = threading.Event()
        else:
            shield.stop()
        return "late-synthetic-id", ""

    process.communicate = communicate
    monkeypatch.setattr(shadow_shield.subprocess, "Popen", lambda *_a, **_k: process)
    shield.set_health(41, "previous coverage")
    assert shield._take_vss_snapshot() is None
    assert shield._snapshots == 0
    assert shield.health == 41


def test_vss_retains_fixed_command_hidden_window_and_90_second_deadline(shield, monkeypatch):
    process = _Process()
    launched = []
    clock = iter((0.0, 0.0, 90.1))
    monkeypatch.setattr(shadow_shield.time, "monotonic", lambda: next(clock))

    def communicate(*, timeout):
        if process.killed:
            return "", ""
        raise subprocess.TimeoutExpired("synthetic", timeout)

    def launch(args, **kwargs):
        launched.append((args, kwargs))
        return process

    process.communicate = communicate
    monkeypatch.setattr(shadow_shield.subprocess, "Popen", launch)
    assert shield._take_vss_snapshot() is None
    assert process.killed == 1
    assert shield.health == 70
    assert "90 seconds" in shield.health_note
    command, options = launched[0]
    assert command[:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
    assert ".Create('C:\\','ClientAccessible')" in command[4]
    assert options["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert "shell" not in options


def test_cancel_cleanup_does_not_close_reader_owned_pipes_after_timeout(shield, monkeypatch):
    process = _Process()
    waits = []

    class ReaderOwnedPipe:
        def close(self):
            pytest.fail("synchronous close could block on the Windows reader's stream lock")

    process.stdout = ReaderOwnedPipe()
    process.stderr = ReaderOwnedPipe()

    def communicate(*, timeout):
        waits.append(timeout)
        shield.stop()
        raise subprocess.TimeoutExpired("synthetic", timeout)

    process.communicate = communicate
    monkeypatch.setattr(shadow_shield.subprocess, "Popen", lambda *_a, **_k: process)
    assert shield._take_vss_snapshot() is None
    assert process.killed == 1
    assert waits == [0.25, 1.0]


def test_success_and_unavailable_vss_publish_real_coverage(shield, monkeypatch):
    process = _Process()
    monkeypatch.setattr(shadow_shield.subprocess, "Popen", lambda *_a, **_k: process)
    assert shield._take_vss_snapshot() == "synthetic-shadow-id"
    assert shield._snapshots == 1
    assert shield.health == 100
    process.returncode = 1
    process.communicate = lambda **_: ("", "synthetic denied")
    assert shield._take_vss_snapshot() is None
    assert shield.health == 70
    assert "rc=1" in shield.health_note


def test_missing_powershell_preserves_hourly_attempt_limit(shield, monkeypatch):
    calls = []
    now = [10000.0]
    monkeypatch.setattr(shadow_shield.time, "time", lambda: now[0])
    monkeypatch.setattr(shield, "_protected_files", lambda: iter(()))

    def missing(*_args, **_kwargs):
        calls.append(1)
        raise FileNotFoundError("synthetic missing PowerShell")

    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds
        if len(sleeps) == 2:
            shield.stop()

    monkeypatch.setattr(shadow_shield.subprocess, "Popen", missing)
    monkeypatch.setattr(shield, "sleep", sleep)
    shield.run()
    assert calls == [1]
    assert shield._last_vss == 10000.0
    assert shield.health == 60
    assert "unavailable" in shield.health_note


def test_cache_copy_stop_removes_partial_artifact_and_does_not_mark_seen(shield, tmp_path, monkeypatch):
    source = tmp_path / "large.txt"
    source.write_bytes(b"x" * (shadow_shield.CACHE_CHUNK_BYTES * 2))
    real_open = open

    class Reader:
        def __enter__(self):
            self.handle = real_open(source, "rb")
            return self

        def __exit__(self, *_):
            self.handle.close()

        def fileno(self):
            return self.handle.fileno()

        def read(self, size):
            result = self.handle.read(size)
            shield.stop()
            return result

    monkeypatch.setattr(shadow_shield, "open", lambda *_a, **_k: Reader(), raising=False)
    outcome, _ = shield._cache_version(str(source))
    assert outcome == "cancelled"
    assert not list(shield._cache_dir.rglob("*.bak"))
    assert not list(shield._cache_dir.rglob("*.tmp"))
    assert str(source) not in shield._seen_mtime
    assert not shield.first_cycle_complete


def test_completed_cache_version_still_uses_exact_artifact_restore(shield, tmp_path, monkeypatch):
    protected = tmp_path / "protected"
    protected.mkdir()
    source = protected / "document.txt"
    source.write_bytes(b"clean version")
    monkeypatch.setattr(shadow_shield, "PROTECTED_DIRS", [str(protected)])
    assert shield._cache_version(str(source)) == ("cached", 13)
    assert shield._cache_version(str(source)) == ("unchanged", 0)
    artifact = shield.prepare_rollback_artifact(str(source), before_ts=time.time() + 5)
    assert artifact is not None
    source.write_bytes(b"changed version")
    assert shield.restore_rollback_artifact(artifact)["restored"] == [str(source)]
    assert source.read_bytes() == b"clean version"


def test_cache_slices_yield_after_real_work_with_partial_coverage(shield, monkeypatch):
    monkeypatch.setattr(shadow_shield, "CACHE_SLICE_FILES", 2)
    monkeypatch.setattr(shadow_shield, "CACHE_SLICE_SECONDS", 100.0)
    monkeypatch.setattr(shield, "_protected_files", lambda: iter(("one", "two", "three")))
    monkeypatch.setattr(shield, "_cache_version", lambda _path: ("unchanged", 0))
    shield._last_vss = time.time()
    shield._vss_health = 70
    shield._vss_note = "synthetic VSS denied"
    waits = []

    def sleep(seconds):
        waits.append((seconds, shield.health, shield.health_note))
        shield.mark_cycle_complete(interval_seconds=seconds)
        if seconds == shadow_shield.POLL_S:
            shield.stop()

    monkeypatch.setattr(shield, "sleep", sleep)
    shield.run()
    assert waits[0][0] == shadow_shield.CACHE_YIELD_SECONDS
    assert waits[0][1] == 50
    assert "coverage PARTIAL" in waits[0][2] and "unchanged=2" in waits[0][2]
    assert "pass complete" in waits[-1][2] and "unchanged=3" in waits[-1][2]
    assert waits[-1][1] == 70
    assert shield.first_cycle_complete


def test_retention_is_per_key_and_bounds_unexpected_directory_growth(shield, tmp_path):
    keydir = tmp_path / "versions"
    keydir.mkdir()
    for number in range(shadow_shield.RETAIN_VERSIONS + 1):
        path = keydir / f"{number}.bak"
        path.write_bytes(b"x")
        os.utime(path, (number, number))
    shield._prune(keydir)
    assert len(list(keydir.glob("*.bak"))) == shadow_shield.RETAIN_VERSIONS
    for number in range(1000, 1000 + shadow_shield.MAX_PRUNE_ENTRIES):
        (keydir / f"{number}.bak").write_bytes(b"x")
    before = set(keydir.iterdir())
    shield._prune(keydir)
    assert set(keydir.iterdir()) == before
    assert shield._prune_errors == 1


def test_registered_budget_covers_vss_without_false_heartbeat(shield, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(shadow_shield.time, "monotonic", lambda: now[0])
    shield._angerona_contract = build_capability_contract(shield, capability_id="angerona.shadow-shield")
    assert shield._watchdog_startup_budget_seconds() == 120.0
    shield._thread = SimpleNamespace(is_alive=lambda: True)
    shield.status = "running"
    shield._generation_started_at = 100.0
    shield._watchdog_deadline_at = 220.0
    now[0] = 195.0
    snapshot = shield.operational_snapshot()
    assert not snapshot["first_cycle_complete"]
    assert WatchdogMonitor._module_fault(snapshot) is None
    now[0] = 220.1
    assert "startup deadline" in WatchdogMonitor._module_fault(shield.operational_snapshot())
    shield.mark_cycle_complete(interval_seconds=15.0)
    now[0] += 134.0
    assert WatchdogMonitor._module_fault(shield.operational_snapshot()) is None
    now[0] += 2.0
    assert "deadline missed" in WatchdogMonitor._module_fault(shield.operational_snapshot())
