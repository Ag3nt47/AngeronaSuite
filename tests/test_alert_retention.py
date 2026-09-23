"""Disposable alert retention: real files, links, custody, bounds and worker lifetime."""
from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid

import pytest

from angerona.core import alert_retention as retention


def archive(root, size=128, age=0):
    directory = root / "diagnostics"
    directory.mkdir(exist_ok=True, mode=0o700)
    path = directory / f"runtime_alerts.{time.time_ns()}.{uuid.uuid4().hex}.log"
    with path.open("wb") as stream:
        stream.truncate(size)
    stamp = time.time() - age * 86400
    os.utime(path, (stamp, stamp))
    return path


def wait_for(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate()


@pytest.mark.parametrize("config", [None, {}, {"alert_retention_days": None},
    {"alert_retention_enabled": "false", "alert_retention_days": True,
     "alert_retention_max_mib": "256"},
    {"alert_retention_days": -1, "alert_retention_max_mib": 999999}])
def test_bad_configuration_uses_independent_safe_defaults(config):
    assert retention.RetentionPolicy.from_config(config) == retention.RetentionPolicy()


def test_configuration_roundtrip():
    config = {"alert_retention_enabled": False, "alert_retention_days": 90,
              "alert_retention_max_mib": 1024}
    assert retention.RetentionPolicy.from_config(config) == retention.RetentionPolicy(False, 90, 1024)


@pytest.mark.parametrize("kwargs", [{"enabled": 1}, {"days": 0}, {"days": 3651},
                                      {"max_mib": 7}, {"max_mib": 16385}])
def test_invalid_explicit_policy_rejected(kwargs):
    with pytest.raises(ValueError):
        retention.RetentionPolicy(**kwargs)


def test_cleanup_empty_root_does_not_create_directories(tmp_path):
    assert retention.cleanup_alert_archives(tmp_path)["status"] == "clean"
    assert not list(tmp_path.iterdir())


def test_age_cleanup_is_idempotent_and_excludes_unrelated_and_active_files(tmp_path):
    old = archive(tmp_path, age=31)
    recent = archive(tmp_path, age=29)
    directory = old.parent
    protected = [directory / name for name in (
        "runtime_alerts.log", "crash.log", "dlq_events.json", "receipt.ndjson",
        "runtime_alerts.1.unsafe.log", "export.log", "events.sqlite3")]
    for path in protected:
        path.write_bytes(b"preserved")
        os.utime(path, (0, 0))
    first = retention.cleanup_alert_archives(tmp_path)
    assert first["deleted_files"] == 1 and first["deleted_bytes"] == 128
    assert not old.exists() and recent.exists()
    assert all(path.read_bytes() == b"preserved" for path in protected)
    assert retention.cleanup_alert_archives(tmp_path)["deleted_files"] == 0


def test_quota_prunes_oldest_first_and_counts_active_bytes(tmp_path):
    old = archive(tmp_path, 4 * 1024**2, age=2)
    recent = archive(tmp_path, 4 * 1024**2, age=1)
    active = old.parent / retention.ACTIVE_NAME
    with active.open("wb") as stream:
        stream.truncate(3 * 1024**2)
    result = retention.cleanup_alert_archives(tmp_path, retention.RetentionPolicy(max_mib=8))
    assert not old.exists() and recent.exists() and active.exists()
    assert result["deleted_files"] == 1 and result["managed_bytes"] == 7 * 1024**2
    assert not result["quota_pressure"]


def test_disabled_retention_keeps_old_and_oversized_archives(tmp_path):
    old = archive(tmp_path, 20 * 1024**2, age=400)
    result = retention.cleanup_alert_archives(tmp_path, retention.RetentionPolicy(False, 1, 8))
    assert result["status"] == "disabled" and old.exists()


def test_pin_blocks_age_and_quota_then_can_be_released(tmp_path):
    old = archive(tmp_path, 9 * 1024**2, age=31)
    retention.pin_archive(tmp_path, old.name)
    result = retention.cleanup_alert_archives(tmp_path, retention.RetentionPolicy(max_mib=8))
    assert old.exists() and result["pinned_files"] == 1
    assert result["quota_pressure"] and result["status"] == "quota-pressure"
    retention.pin_archive(tmp_path, old.name, False)
    assert retention.cleanup_alert_archives(tmp_path)["deleted_files"] == 1


def test_active_oversize_only_reports_pressure_and_is_never_cleaner_deleted(tmp_path):
    retention.append_runtime_alert(tmp_path, "first")
    active = tmp_path / "diagnostics" / retention.ACTIVE_NAME
    with active.open("ab") as stream:
        stream.truncate(9 * 1024**2)
    result = retention.cleanup_alert_archives(tmp_path, retention.RetentionPolicy(max_mib=8))
    assert result["quota_pressure"] and active.exists() and result["deleted_files"] == 0


def test_append_rotates_legacy_oversize_without_loading_or_truncating_it(tmp_path):
    retention.append_runtime_alert(tmp_path, "first")
    active = tmp_path / "diagnostics" / retention.ACTIVE_NAME
    with active.open("ab") as stream:
        stream.truncate(20 * 1024**2)
    retention.append_runtime_alert(tmp_path, "new tail")
    archives = [path for path in active.parent.iterdir() if retention._ARCHIVE.fullmatch(path.name)]
    assert len(archives) == 1 and archives[0].stat().st_size == 20 * 1024**2
    assert b"new tail" in active.read_bytes() and active.stat().st_size < 100


def test_append_bounds_unicode_input_and_segment_size(tmp_path, monkeypatch):
    monkeypatch.setattr(retention, "SEGMENT_BYTES", retention.MAX_LINE_BYTES * 2)
    for _ in range(5):
        retention.append_runtime_alert(tmp_path, "\U0001f6a8" * 100000)
    for path in (tmp_path / "diagnostics").iterdir():
        if path.suffix == ".log":
            assert path.stat().st_size <= retention.MAX_LINE_BYTES * 2
            text = path.read_text(encoding="utf-8")
            assert "[truncated]" in text


def test_hardlinked_archive_and_active_are_refused(tmp_path):
    old = archive(tmp_path, age=31)
    outside = tmp_path / "evidence.txt"
    os.link(old, outside)
    result = retention.cleanup_alert_archives(tmp_path)
    assert old.exists() and outside.exists() and result["unsafe_files"] == 1
    active = old.parent / retention.ACTIVE_NAME
    os.link(outside, active)
    with pytest.raises(ValueError, match="single-link"):
        retention.append_runtime_alert(tmp_path, "must not write")
    assert outside.stat().st_size == 128


def test_leaf_symlink_cannot_delete_target(tmp_path):
    old = archive(tmp_path, age=31)
    old.unlink()
    outside = tmp_path / "evidence.txt"
    outside.write_text("evidence", encoding="utf-8")
    try:
        old.symlink_to(outside)
    except OSError:
        pytest.skip("Account cannot create symbolic links")
    result = retention.cleanup_alert_archives(tmp_path)
    assert result["unsafe_files"] == 1 and outside.read_text(encoding="utf-8") == "evidence"
    assert old.is_symlink()


def test_redirected_directory_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    real = archive(outside, age=31)
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    try:
        (redirected / "diagnostics").symlink_to(real.parent, target_is_directory=True)
    except OSError:
        pytest.skip("Account cannot create symbolic links")
    assert retention.cleanup_alert_archives(redirected)["status"] == "unavailable"
    with pytest.raises((ValueError, OSError)):
        retention.append_runtime_alert(redirected, "must not write")
    assert real.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction custody")
def test_native_windows_directory_junction_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    original = archive(outside, age=31)
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    result = subprocess.run(
        [os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"),
         "/d", "/c", "mklink", "/J", str(redirected / "diagnostics"), str(original.parent)],
        capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert retention.cleanup_alert_archives(redirected)["status"] == "unavailable"
    with pytest.raises((ValueError, OSError)):
        retention.append_runtime_alert(redirected, "must not write outside")
    assert original.exists() and not (original.parent / retention.ACTIVE_NAME).exists()


def test_reparse_attribute_is_rejected_even_when_mode_is_regular():
    from types import SimpleNamespace
    info = SimpleNamespace(st_mode=0o100600, st_file_attributes=0x400, st_nlink=1)
    with pytest.raises(ValueError, match="reparse"):
        retention._plain(info)


def test_lease_hardlink_refusal_preserves_target(tmp_path):
    old = archive(tmp_path, age=31)
    protected = tmp_path / "protected.txt"
    protected.write_bytes(b"protected")
    os.link(protected, old.parent / retention._LOCK_NAME)
    assert retention.cleanup_alert_archives(tmp_path)["status"] == "unavailable"
    with pytest.raises(ValueError):
        retention.append_runtime_alert(tmp_path, "must not append")
    assert protected.read_bytes() == b"protected" and old.exists()


def test_concurrent_open_writer_is_not_deleted(tmp_path):
    old = archive(tmp_path, age=31)
    with retention._directory(tmp_path, create=False) as directory:
        with directory.open(old.name):
            report = retention.cleanup_alert_archives(tmp_path)
    assert old.exists() and report["unsafe_files"] == 1


def test_identity_replacement_between_scan_and_delete_is_not_removed(tmp_path, monkeypatch):
    old = archive(tmp_path, age=31)
    original = retention._Directory.open
    def racing_open(self, name, **kwargs):
        if name == old.name:
            old.unlink()
            old.write_bytes(b"new evidence object")
        return original(self, name, **kwargs)
    monkeypatch.setattr(retention._Directory, "open", racing_open)
    result = retention.cleanup_alert_archives(tmp_path)
    assert old.read_bytes() == b"new evidence object"
    assert result["deleted_files"] == 0 and result["unsafe_files"] == 1


def test_deletion_and_enumeration_caps_report_incomplete(tmp_path, monkeypatch):
    for _ in range(7):
        archive(tmp_path, age=31)
    monkeypatch.setattr(retention, "MAX_DELETIONS", 2)
    result = retention.cleanup_alert_archives(tmp_path)
    assert result["deleted_files"] == 2 and result["incomplete"]
    monkeypatch.setattr(retention, "MAX_ENTRIES", 2)
    result = retention.cleanup_alert_archives(tmp_path)
    assert result["incomplete"]


def test_process_lease_serializes_writer_and_cleanup(tmp_path):
    old = archive(tmp_path, age=31)
    with retention._transaction(tmp_path, create=False):
        assert retention.cleanup_alert_archives(tmp_path)["status"] == "unavailable"
        with pytest.raises(OSError):
            retention.append_runtime_alert(tmp_path, "contended")
    assert old.exists()


def test_worker_queue_is_bounded_without_touching_disk_before_start(tmp_path):
    worker = retention.AlertRetentionWorker(tmp_path)
    assert all(worker.append("message") for _ in range(256))
    assert not worker.append("overflow")
    assert worker.snapshot()["dropped"] == 1 and not list(tmp_path.iterdir())
    assert worker.stop()


@pytest.mark.parametrize("argument", [{"startup_grace": float("nan")},
                                      {"interval": float("inf")}, {"policy": object()}])
def test_worker_rejects_invalid_parameters_before_thread_start(tmp_path, argument):
    with pytest.raises((ValueError, TypeError)):
        retention.AlertRetentionWorker(tmp_path, **argument)


def test_worker_cleanup_grace_explicit_request_and_policy_update(tmp_path):
    old = archive(tmp_path, age=31)
    worker = retention.AlertRetentionWorker(tmp_path, startup_grace=60)
    worker.start()
    try:
        worker.append("worker writes")
        wait_for(lambda: (old.parent / retention.ACTIVE_NAME).exists())
        assert old.exists() and worker.snapshot()["status"] == "waiting"
        worker.request_cleanup()
        wait_for(lambda: not old.exists())
        worker.update_policy(retention.RetentionPolicy(False))
        wait_for(lambda: worker.snapshot()["status"] == "disabled")
        assert worker.snapshot()["writer_errors"] == 0
    finally:
        assert worker.stop()


def test_worker_concurrent_producers_and_shutdown_drain(tmp_path):
    worker = retention.AlertRetentionWorker(tmp_path)
    worker.start()
    threads = [threading.Thread(target=lambda i=i: [worker.append(f"{i}:{n}")
                                                   for n in range(20)]) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert worker.stop(timeout=10)
    raw = (tmp_path / "diagnostics" / retention.ACTIVE_NAME).read_text(encoding="utf-8")
    assert len(raw.splitlines()) == 80 and worker.snapshot()["writer_errors"] == 0
    assert not worker.append("after stop")


def test_pin_rejects_arbitrary_names(tmp_path):
    with pytest.raises(ValueError):
        retention.pin_archive(tmp_path, "../evidence.log")


def test_resumable_inventory_eventually_reaches_archives_behind_unmanaged_prefix(tmp_path, monkeypatch):
    directory = tmp_path / "diagnostics"
    directory.mkdir()
    for index in range(9):
        (directory / f"aaa_unmanaged_{index}").write_bytes(b"keep")
    old = archive(tmp_path, age=31)
    original_entries = retention._Directory.entries
    class OrderedEntries:
        def __init__(self, values):
            self.values = iter(values)
            self.closed = False
        def __next__(self):
            return next(self.values)
        def close(self):
            self.closed = True
    def ordered(self):
        with original_entries(self) as entries:
            return OrderedEntries(sorted(entries, key=lambda entry: entry.name))
    monkeypatch.setattr(retention._Directory, "entries", ordered)
    monkeypatch.setattr(retention, "MAX_ENTRIES", 3)
    cursor = retention.RetentionScanCursor()
    try:
        first = retention.cleanup_alert_archives(tmp_path, cursor=cursor)
        assert first["incomplete"] and first["deleted_files"] == 0 and old.exists()
        for _ in range(5):
            result = retention.cleanup_alert_archives(tmp_path, cursor=cursor)
            if not old.exists():
                break
        assert not old.exists()
        assert all(path.read_bytes() == b"keep" for path in directory.glob("aaa_*"))
        assert result["deleted_files"] == 1
    finally:
        cursor.close()


def test_partial_inventory_does_not_claim_quota_coverage(tmp_path, monkeypatch):
    for _ in range(5):
        archive(tmp_path, 4 * 1024**2)
    monkeypatch.setattr(retention, "MAX_ENTRIES", 2)
    cursor = retention.RetentionScanCursor()
    try:
        result = retention.cleanup_alert_archives(tmp_path, retention.RetentionPolicy(max_mib=8), cursor=cursor)
        assert result["incomplete"] and result["deleted_files"] == 0
        for _ in range(4):
            result = retention.cleanup_alert_archives(tmp_path, retention.RetentionPolicy(max_mib=8), cursor=cursor)
            if cursor.iterator is None:
                break
        assert result["deleted_files"] == 3 and result["managed_bytes"] == 8 * 1024**2
    finally:
        cursor.close()


def test_locked_oldest_prefix_does_not_exclude_later_deletable_candidate(tmp_path, monkeypatch):
    locked = [archive(tmp_path, age=40) for _ in range(4)]
    eligible = archive(tmp_path, age=31)
    monkeypatch.setattr(retention, "MAX_DELETIONS", 2)
    import contextlib
    with retention._directory(tmp_path, create=False) as directory, contextlib.ExitStack() as stack:
        for path in locked:
            stack.enter_context(directory.open(path.name))
        result = retention.cleanup_alert_archives(tmp_path)
    assert not eligible.exists() and all(path.exists() for path in locked)
    assert result["deleted_files"] == 1 and result["unsafe_files"] == 4
