"""Slow routine scan work yields before count-only batch limits."""
from __future__ import annotations

import zipfile
from types import SimpleNamespace

import pytest

from angerona.core import background_pacing
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.security_scan_center import (
    ScanCancellationToken,
    SecurityScanCenter,
    _TraversalState,
)
from angerona.modules.yara_scanner import YaraScannerModule


@pytest.fixture
def pressured(monkeypatch):
    monkeypatch.setattr(
        background_pacing, "get_pacing_controller",
        lambda: SimpleNamespace(batch_delay=lambda: 0.05),
    )


def _slow_file_scan(tmp_path, monkeypatch, *, deadline=120.0):
    now = [0.0]
    center = SecurityScanCenter(monotonic=lambda: now[0], max_duration_seconds=deadline)
    paths = [tmp_path / f"inert-{index}.txt" for index in range(3)]
    for path in paths:
        path.write_bytes(b"inert")
    monkeypatch.setattr(center, "_validated_local_target", lambda _: tmp_path)
    # Isolate the file-loop checkpoint from discovery's separate checkpoints.
    monkeypatch.setattr(
        center, "_iter_local_files",
        lambda _root, **_kwargs: ((path, path.relative_to(tmp_path)) for path in paths),
    )
    scans = []

    class Scanner:
        def scan(self, content):
            scans.append(content)
            now[0] += 0.1
            return SimpleNamespace(matching_rules=[])

    monkeypatch.setattr(center, "_make_yara_scanner", lambda: (Scanner(), "active"))
    return center, now, scans


def test_slow_file_scan_yields_and_cancels_before_eight_files(tmp_path, monkeypatch, pressured):
    center, _now, scans = _slow_file_scan(tmp_path, monkeypatch)
    token = ScanCancellationToken()
    waits = []

    def wait(delay):
        waits.append(delay)
        token.cancel()
        return True

    monkeypatch.setattr(token, "wait", wait)
    result = center.scan_path(tmp_path, cancellation=token)
    assert result.status == "cancelled"
    assert result.metrics["files_scanned"] == len(scans) == 1
    assert waits == [pytest.approx(0.05)]


def test_scan_pacing_wait_keeps_original_wall_deadline(tmp_path, monkeypatch, pressured):
    center, now, scans = _slow_file_scan(tmp_path, monkeypatch, deadline=0.12)
    token = ScanCancellationToken()
    waits = []

    def wait(delay):
        waits.append(delay)
        now[0] += delay
        return False

    monkeypatch.setattr(token, "wait", wait)
    result = center.scan_path(tmp_path, cancellation=token)
    assert result.status == "limited" and result.metrics["timed_out"]
    assert result.metrics["files_scanned"] == len(scans) == 1
    assert waits == [pytest.approx(0.02)]


def test_slow_discovery_yields_before_256_entries(tmp_path, monkeypatch, pressured):
    import angerona.core.security_scan_center as scan_module

    for index in range(3):
        (tmp_path / f"inert-{index}.txt").write_bytes(b"inert")
    now = [0.0]
    center = SecurityScanCenter(monotonic=lambda: now[0])
    token, state = ScanCancellationToken(), _TraversalState()
    real_scandir = scan_module.os.scandir
    waits = []

    class SlowEntries:
        def __enter__(self):
            self.entries = real_scandir(tmp_path)
            return self

        def __iter__(self):
            return self

        def __next__(self):
            entry = next(self.entries)
            now[0] += 0.1
            return entry

        def __exit__(self, *_args):
            self.entries.close()

    def wait(delay):
        waits.append(delay)
        token.cancel()
        return True

    monkeypatch.setattr(scan_module.os, "scandir", lambda _: SlowEntries())
    monkeypatch.setattr(token, "wait", wait)
    paths = list(center._iter_local_files(tmp_path, cancellation=token, traversal=state))
    assert paths == []
    assert state.cancelled and state.entries_seen == 1
    assert waits == [pytest.approx(0.05)]


def test_pressure_yields_keep_complete_file_coverage(tmp_path, monkeypatch, pressured):
    center, now, scans = _slow_file_scan(tmp_path, monkeypatch)
    token = ScanCancellationToken()
    waits = []

    def wait(delay):
        waits.append(delay)
        now[0] += delay
        return False

    monkeypatch.setattr(token, "wait", wait)
    result = center.scan_path(tmp_path, cancellation=token)
    assert result.status == "completed"
    assert result.metrics["files_scanned"] == len(scans) == 3
    assert result.metrics["bytes_scanned"] == 3 * len(b"inert")
    assert len(waits) == 2 and all(delay == pytest.approx(0.05) for delay in waits)


@pytest.mark.parametrize("stop_at", [None, 2])
def test_archive_checkpoints_preserve_findings_and_honest_coverage(tmp_path, monkeypatch, stop_at):
    target = tmp_path / "inert.zip"
    with zipfile.ZipFile(target, "w") as archive:
        for name in ("one", "two", "three"):
            archive.writestr(name, b"inert")
    bus = EventBus()
    bus.arm(BusAuthority(b"p" * 32))
    module = YaraScannerModule()
    module.bind(bus)
    checked, scanned, opened = [], [], []

    class Scanner:
        def scan(self, content):
            scanned.append(content)
            rules = [SimpleNamespace(identifier="Inert_Outer_Probe")] if content.startswith(b"PK") else []
            return SimpleNamespace(matching_rules=rules)

    def checkpoint(completed, *, batch_size):
        assert batch_size == 8
        checked.append(completed)
        return stop_at is None or completed < stop_at

    real_open = zipfile.ZipFile.open

    def archive_open(self, member, *args, **kwargs):
        opened.append(member.filename)
        return real_open(self, member, *args, **kwargs)

    monkeypatch.setattr(module, "background_checkpoint", checkpoint)
    monkeypatch.setattr(zipfile.ZipFile, "open", archive_open)
    outcome = module._scan_file(Scanner(), target)
    event = bus.recent(1)[0]
    assert module.verify_detection_event(event)
    assert event.details["rule"] == "Inert_Outer_Probe"
    if stop_at is None:
        assert outcome == "scanned"
        assert checked == [1, 2, 3] and len(scanned) == 4
        assert opened == ["one", "two", "three"]
        assert event.details["scan_complete"] is True
        assert module._scan_cache
    else:
        assert outcome == "failed" and not module._scan_cache
        assert checked == [1, 2] and len(scanned) == 2
        assert opened == ["one"]
        assert event.details["scan_complete"] is False
        assert "stopped before complete coverage" in event.details["coverage_reason"]
