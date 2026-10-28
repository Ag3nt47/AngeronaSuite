"""Inert recovery-cache admission; never create native shadows or delete evidence."""
from __future__ import annotations

import os
import time
import sys
import threading
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.modules import shadow_shield
from angerona.modules.shadow_shield import ShadowShield


@pytest.fixture
def shield(tmp_path, monkeypatch):
    module = ShadowShield()
    module._cache_dir = tmp_path / "shadow_cache"
    module.emit = lambda *_args, **_kwargs: None
    monkeypatch.setattr(shadow_shield.shutil, "disk_usage", lambda _path: SimpleNamespace(free=100 * 1024**3))
    monkeypatch.setattr(shadow_shield.subprocess, "Popen", lambda *_a, **_k: pytest.fail("native VSS forbidden"))
    return module


def existing(shield, source, content=b"prior recovery version"):
    keydir = shield._keydir(str(source))
    keydir.mkdir(parents=True, exist_ok=True)
    (keydir / "_source.txt").write_bytes(str(source).encode("utf-8"))
    version = keydir / "1.bak"
    version.write_bytes(content)
    return keydir, version


def test_restart_inventory_counts_existing_bytes_sources_and_sidecars(shield, tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"new version")
    keydir, old = existing(shield, source)
    expected = len(old.read_bytes()) + len(str(source).encode("utf-8"))
    assert shield._inventory_cache()
    assert (shield._cache_bytes, shield._cache_entries, shield._cache_sources) == (expected, 3, 1)
    assert shield._cache_version(str(source)) == ("cached", 11)
    assert old.read_bytes() == b"prior recovery version"
    assert len(list(keydir.glob("*.bak"))) == 2
    assert shield._cache_bytes == expected + 11


def test_byte_quota_includes_sidecar_and_full_staged_version(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"12345")
    sidecar_bytes = len(str(source).encode("utf-8"))
    monkeypatch.setattr(shadow_shield, "MAX_CACHE_BYTES", sidecar_bytes + 4)
    assert shield._cache_version(str(source)) == ("skipped", 0)
    assert not shield._keydir(str(source)).exists()
    assert "quota" in shield._cache_storage_hold


def test_exact_byte_quota_boundary_is_admitted(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"12345")
    monkeypatch.setattr(shadow_shield, "MAX_CACHE_BYTES", len(str(source).encode("utf-8")) + 5)
    assert shield._cache_version(str(source)) == ("cached", 5)
    assert shield._cache_bytes == shadow_shield.MAX_CACHE_BYTES


def test_quota_refusal_preserves_previous_backups_and_holds_without_rescan(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"new content")
    keydir, old = existing(shield, source)
    baseline = {item.name: item.read_bytes() for item in keydir.iterdir()}
    monkeypatch.setattr(shadow_shield, "MAX_CACHE_BYTES", sum(map(len, baseline.values())) + 1)
    assert shield._cache_version(str(source)) == ("skipped", 0)
    monkeypatch.setattr(shadow_shield.os, "scandir", lambda *_: pytest.fail("held cache rescanned"))
    assert shield._cache_version(str(source)) == ("skipped", 0)
    assert not shield._inventory_cache()
    assert old.read_bytes() == baseline[old.name]
    for name, content in baseline.items():
        assert (keydir / name).read_bytes() == content


@pytest.mark.parametrize("limit", ["MAX_CACHE_ENTRIES", "MAX_CACHE_SOURCES"])
def test_existing_inventory_limit_refuses_before_new_copy(shield, tmp_path, monkeypatch, limit):
    source = tmp_path / "document.txt"
    source.write_bytes(b"new")
    _, old = existing(shield, source)
    existing(shield, tmp_path / "second.txt")
    monkeypatch.setattr(shadow_shield, limit, 1)
    assert shield._cache_version(str(source)) == ("skipped", 0)
    assert "limit" in shield._cache_storage_hold
    assert old.read_bytes() == b"prior recovery version"


def test_missing_sidecar_reserves_an_entry_before_writing(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"new")
    keydir = shield._keydir(str(source))
    keydir.mkdir(parents=True)
    (keydir / "1.bak").write_bytes(b"prior")
    monkeypatch.setattr(shadow_shield, "MAX_CACHE_ENTRIES", 3)
    assert shield._cache_version(str(source)) == ("skipped", 0)
    assert not (keydir / "_source.txt").exists()


def test_inventory_rejects_hardlinked_files(shield, tmp_path):
    source = tmp_path / "document.txt"
    keydir, old = existing(shield, source)
    os.link(old, keydir / "2.bak")
    assert not shield._inventory_cache()
    assert "linked" in shield._cache_storage_hold
    assert old.read_bytes() == b"prior recovery version"


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_inventory_rejects_reparse_objects_without_traversing_them(shield, tmp_path, monkeypatch, kind):
    source = tmp_path / "document.txt"
    keydir, old = existing(shield, source)
    marked = keydir if kind == "directory" else old
    real_scandir = os.scandir

    class Entry:
        def __init__(self, child):
            self.child = child
            self.name, self.path = child.name, child.path

        def stat(self, *, follow_symlinks):
            info = self.child.stat(follow_symlinks=follow_symlinks)
            if Path(self.path) != marked:
                return info
            return SimpleNamespace(
                st_file_attributes=0x400, st_mode=info.st_mode,
                st_nlink=info.st_nlink, st_size=info.st_size,
            )

    class Scan:
        def __init__(self, path):
            assert Path(path) != marked, "reparse directory traversed"
            self.scan = real_scandir(path)

        def __enter__(self):
            return (Entry(child) for child in self.scan)

        def __exit__(self, *_):
            self.scan.close()

    monkeypatch.setattr(shadow_shield.os, "scandir", Scan)
    assert not shield._inventory_cache()
    assert "linked" in shield._cache_storage_hold


def test_incomplete_inventory_io_failure_is_held(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    existing(shield, source)

    def denied(_):
        raise PermissionError("inert unavailable directory")

    monkeypatch.setattr(shadow_shield.os, "scandir", denied)
    assert not shield._inventory_cache()
    assert not shield._cache_accounted
    assert "unavailable" in shield._cache_storage_hold


def test_inventory_deadline_is_a_hold_not_partial_accounting(shield, tmp_path, monkeypatch):
    existing(shield, tmp_path / "document.txt")
    ticks = iter((0.0, 3.0))
    monkeypatch.setattr(shadow_shield.time, "monotonic", lambda: next(ticks))
    assert not shield._inventory_cache()
    assert not shield._cache_accounted
    assert "time limit" in shield._cache_storage_hold


def test_observed_directory_change_holds_cached_accounting(shield, tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"new")
    keydir, _ = existing(shield, source)
    assert shield._inventory_cache()
    before = shield._cache_directory_stamps[keydir]
    (keydir / "unexpected.tmp").write_bytes(b"external writer")
    # Windows may coalesce/defer directory timestamp changes after rapid file
    # creation. Exercise an explicitly observed stamp change, rather than assume
    # that one new entry necessarily publishes a new timestamp immediately.
    metadata = keydir.lstat()
    os.utime(keydir, ns=(metadata.st_atime_ns, before[2] + 2_000_000_000))
    assert shield._directory_stamp(keydir.lstat()) != before
    assert shield._cache_version(str(source)) == ("skipped", 0)
    assert "outside the writer" in shield._cache_storage_hold


def test_free_space_accounts_for_entire_copy_and_sidecar(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"new")
    required = shadow_shield.MIN_FREE_BYTES + 3 + len(str(source).encode("utf-8"))
    monkeypatch.setattr(shadow_shield.shutil, "disk_usage", lambda _: SimpleNamespace(free=required - 1))
    assert shield._cache_version(str(source)) == ("skipped", 0)
    assert not shield._keydir(str(source)).exists()
    assert "reserve" in shield.health_note


def test_source_growth_never_writes_beyond_reserved_size(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"old")
    real_open = open

    class GrowingReader:
        def __enter__(self):
            self.handle = real_open(source, "rb")
            return self

        def __exit__(self, *_):
            self.handle.close()

        def fileno(self):
            return self.handle.fileno()

        def read(self, _size):
            return b"more than reserved"

    monkeypatch.setattr(shadow_shield, "open", lambda *_a, **_k: GrowingReader(), raising=False)
    assert shield._cache_version(str(source))[0] == "failed"
    keydir = shield._keydir(str(source))
    assert not list(keydir.glob("*.bak"))
    assert not list(keydir.glob("*.tmp"))
    assert str(source) not in shield._seen_mtime


@pytest.mark.parametrize("low_volume", ["target", "cache"])
def test_vss_reserve_refusal_never_launches_or_deletes_shadows(shield, tmp_path, monkeypatch, low_volume):
    checked = []
    target = tmp_path / "target-volume"
    target.mkdir()

    def usage(path):
        checked.append(Path(path))
        low = Path(path) == target if low_volume == "target" else Path(path) != target
        return SimpleNamespace(free=shadow_shield.MIN_FREE_BYTES - 1 if low else 100 * 1024**3)

    monkeypatch.setattr(shadow_shield.shutil, "disk_usage", usage)
    assert shield._take_vss_snapshot(str(target)) is None
    assert shield._last_vss > 0
    assert shield._snapshots == 0
    assert "reserve" in shield._vss_note
    assert target in checked


def test_held_worker_does_not_walk_protected_sources_each_pass(shield, monkeypatch):
    shield._cache_dir.mkdir()
    (shield._cache_dir / "unexpected-directory").mkdir()
    monkeypatch.setattr(shield, "_protected_files", lambda: pytest.fail("held inventory walked user files"))
    shield._last_vss = time.time()
    turns = []

    def sleep(_seconds):
        turns.append(shield.health_note)
        if len(turns) == 2:
            shield.stop()

    monkeypatch.setattr(shield, "sleep", sleep)
    shield.run()
    assert len(turns) == 2
    assert all("LIMITED" in note for note in turns)
    assert shield.health <= 50


def test_default_worker_never_requests_automatic_vss(shield, monkeypatch):
    assert not shield._automatic_vss_enabled
    monkeypatch.setattr(shield, "_protected_files", lambda: iter(()))
    monkeypatch.setattr(shield, "_take_vss_snapshot", lambda: pytest.fail("default automatic VSS"))
    monkeypatch.setattr(shield, "sleep", lambda _: shield.stop())
    shield.run()
    assert "automatic VSS disabled" in shield.health_note


def test_configuration_and_status_are_cached_until_worker_service(shield, monkeypatch):
    monkeypatch.setattr(shadow_shield.os, "scandir", lambda *_: pytest.fail("caller filesystem I/O"))
    monkeypatch.setattr(shadow_shield.shutil, "disk_usage", lambda *_: pytest.fail("caller disk query"))
    shield.configure_storage_policy(cache_enabled=False, vss_enabled=False, max_mib=64, min_free_mib=512)
    assert shield.storage_status()["limit_bytes"] == shadow_shield.MAX_CACHE_BYTES
    shield._service_storage_commands(shield.generation_stop_event())
    status = shield.storage_status()
    assert status["limit_bytes"] == 64 * 1024**2
    assert status["reserve_bytes"] == 512 * 1024**2
    assert status["used_bytes"] is None and status["free_bytes"] is None
    assert "disabled" in status["reason"]
    assert shield._cache_version("never-read") == ("skipped", 0)


@pytest.mark.parametrize("override", [
    {"cache_enabled": 1}, {"vss_enabled": "true"}, {"max_mib": True},
    {"max_mib": 63}, {"max_mib": 16_385}, {"min_free_mib": 511},
    {"min_free_mib": 65_537},
])
def test_invalid_storage_policy_refused(shield, override):
    policy = dict(cache_enabled=True, vss_enabled=False, max_mib=2048, min_free_mib=2048)
    policy.update(override)
    with pytest.raises(ValueError):
        shield.configure_storage_policy(**policy)


def test_identical_policy_does_not_reopen_sticky_storage_hold(shield):
    policy = dict(cache_enabled=True, vss_enabled=False, max_mib=2048, min_free_mib=2048)
    shield.configure_storage_policy(**policy)
    shield._service_storage_commands(shield.generation_stop_event())
    shield._hold_storage("incomplete inventory")
    shield.configure_storage_policy(**policy)
    shield._service_storage_commands(shield.generation_stop_event())
    assert shield.storage_status()["reason"] == "incomplete inventory"


def test_manager_binding_queues_persisted_policy(shield):
    config = SimpleNamespace(shadow_cache_enabled=False, shadow_vss_enabled=True,
                             shadow_cache_max_mib=128, shadow_min_free_mib=1024)
    shield.bind_manager(SimpleNamespace(config=config))
    assert shield._storage_policy_pending == (False, True, 128, 1024, False)


@pytest.mark.parametrize("complete", [True, False])
def test_cleanup_runs_once_on_retained_maintenance_worker(shield, monkeypatch, complete):
    calls = []
    entered = threading.Event()
    release = threading.Event()
    caller = threading.current_thread()

    def cleanup(path, *, stopped):
        assert shield.storage_status()["cleanup_pending"]
        assert threading.current_thread() is not caller
        calls.append((path, stopped))
        entered.set()
        assert release.wait(5)
        return dict(complete=complete, removed_files=0, removed_bytes=0, reason="inert refusal")

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    shield._cache_accounted = True
    shield._hold_storage("prior quota")
    assert shield.request_cache_cleanup()
    try:
        assert entered.wait(5)
        assert not shield.request_cache_cleanup()
        assert calls == [(shield._cache_dir, shield._cache_cleanup_cancel)]
    finally:
        release.set()
        shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    assert not shield.storage_status()["cleanup_pending"]
    assert not shield._cache_accounted
    assert shield.storage_status()["held"] is not complete


def test_queued_warning_block_stops_before_another_source_copy(shield, monkeypatch):
    copied = []
    monkeypatch.setattr(shield, "_protected_files", lambda: iter(("one", "two", "three")))

    def copy(path):
        copied.append(path)
        shield.configure_storage_policy(cache_enabled=False, vss_enabled=False,
                                        max_mib=2048, min_free_mib=2048, review_pending=True)
        return "cached", 0

    monkeypatch.setattr(shield, "_cache_version", copy)
    monkeypatch.setattr(shield, "sleep", lambda _: shield.stop())
    shield.run()
    assert copied == ["one"]
    status = shield.storage_status()
    assert not status["cache_enabled"]
    assert status["held"] and "awaiting storage decision" in status["reason"]
    assert "coverage LIMITED" in shield.health_note


def test_empty_retained_key_directories_do_not_consume_source_quota(shield, tmp_path, monkeypatch):
    shield._cache_dir.mkdir()
    for number in range(3):
        (shield._cache_dir / f"{number:064x}").mkdir()
    monkeypatch.setattr(shadow_shield, "MAX_CACHE_SOURCES", 1)
    assert shield._inventory_cache()
    assert shield._cache_sources == 0
    assert shield._cache_entries == 3
    source = tmp_path / "document.txt"
    source.write_bytes(b"new")
    assert shield._cache_version(str(source)) == ("cached", 3)
    assert shield._cache_sources == 1


def test_status_is_a_copy_of_last_published_worker_projection(shield):
    status = shield.storage_status()
    status["reason"] = "caller mutation"
    assert shield.storage_status()["reason"] == ""
    shield._cache_bytes = 100
    shield._cache_accounted = True
    assert shield.storage_status()["used_bytes"] is None
    shield._publish_storage_status()
    assert shield.storage_status()["used_bytes"] == 100


def test_stopped_module_can_delete_real_owned_recovery_copies(shield, tmp_path):
    shield._cache_dir = tmp_path / "shadow_cache"
    source = tmp_path / "document.txt"
    source.write_bytes(b"source stays")
    _, old = existing(shield, source)
    shield.stop()
    assert shield.request_cache_cleanup()
    shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    assert not shield.storage_status()["cleanup_pending"]
    assert not shield.storage_status()["held"]
    assert not old.exists()
    assert source.read_bytes() == b"source stays"


def test_pending_cleanup_waits_for_owned_copy_lock_without_blocking_caller(shield, monkeypatch):
    entered = threading.Event()
    calls = []

    def cleanup(path, *, stopped):
        calls.append(path)
        entered.set()
        return dict(complete=True, removed_files=0, removed_bytes=0, reason="inert")

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    with shield._cache_io_lock:
        assert shield.request_cache_cleanup()
        assert shield.storage_status()["cleanup_pending"]
        assert not entered.is_set()
        assert shield._cache_version("must-not-read") == ("skipped", 0)
        assert not shield.request_cache_cleanup()
    shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    assert calls == [shield._cache_dir]


def test_stop_cancels_owned_maintenance_without_waiting_on_native_work(shield, monkeypatch):
    entered = threading.Event()
    cancelled = threading.Event()

    def cleanup(path, *, stopped):
        entered.set()
        assert stopped.wait(5)
        cancelled.set()
        return dict(complete=False, removed_files=0, removed_bytes=0, reason="cancelled")

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    assert shield.request_cache_cleanup()
    try:
        assert entered.wait(5)
        shield.stop()
    finally:
        shield._cache_cleanup_cancel.set()
        shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    assert cancelled.is_set()
    assert "cancelled" in shield.storage_status()["reason"]


def test_restarted_writer_fast_refuses_during_previous_maintenance(shield, tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    copied = threading.Event()
    outcomes = []
    source = tmp_path / "document.txt"
    source.write_bytes(b"new generation")

    def cleanup(path, *, stopped):
        entered.set()
        assert release.wait(5)
        return dict(complete=True, removed_files=0, removed_bytes=0, reason="inert")

    def copy():
        outcomes.append(shield._cache_version(str(source)))
        copied.set()

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    assert shield.request_cache_cleanup()
    contender = threading.Thread(target=copy)
    try:
        assert entered.wait(5)
        contender.start()
        assert copied.wait(5)
        assert outcomes == [("skipped", 0)]
        assert not shield._cache_dir.exists()
    finally:
        release.set()
        shield._cache_cleanup_thread.join(5)
        if contender.ident is not None:
            contender.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    assert not contender.is_alive()
    assert copied.is_set()


def test_readonly_versions_still_obey_existing_six_version_retention(shield, tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"original stays")
    keydir = shield._keydir(str(source))
    keydir.mkdir(parents=True)
    for number in range(shadow_shield.RETAIN_VERSIONS + 2):
        version = keydir / f"{number}.bak"
        version.write_bytes(str(number).encode("ascii"))
        os.utime(version, ns=(number * 1_000_000_000, number * 1_000_000_000))
        version.chmod(stat.S_IREAD)
    shield._prune(keydir)
    retained = sorted(int(item.stem) for item in keydir.glob("*.bak"))
    assert retained == list(range(2, shadow_shield.RETAIN_VERSIONS + 2))
    assert shield._prune_errors == 0
    assert not shield._cache_storage_hold
    for number in retained:
        version = keydir / f"{number}.bak"
        assert version.read_bytes() == str(number).encode("ascii")
        if os.name == "nt":
            assert version.lstat().st_file_attributes & 1
    assert source.read_bytes() == b"original stays"


def test_stop_after_copystat_retires_owned_readonly_staging_copy(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"original stays")
    source.chmod(stat.S_IREAD)
    real_copystat = shadow_shield.shutil.copystat
    marked = []

    def copied_attributes(origin, destination):
        real_copystat(origin, destination)
        if os.name == "nt":
            assert destination.lstat().st_file_attributes & 1
        marked.append(destination)
        shield.stop()

    monkeypatch.setattr(shadow_shield.shutil, "copystat", copied_attributes)
    outcome, _ = shield._cache_version(str(source))
    assert outcome == "cancelled"
    assert len(marked) == 1 and not marked[0].exists()
    assert not list(shield._keydir(str(source)).glob("*.bak"))
    assert not shield._cache_storage_hold
    assert source.read_bytes() == b"original stays"
    if os.name == "nt":
        assert source.lstat().st_file_attributes & 1


def test_failed_publication_cleans_readonly_stage_without_changing_original(shield, tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"original stays")
    source.chmod(stat.S_IREAD)
    before = source.lstat()

    def failed_replace(*_args):
        raise PermissionError("inert publication refusal")

    monkeypatch.setattr(shadow_shield.os, "replace", failed_replace)
    assert shield._cache_version(str(source))[0] == "failed"
    assert not list(shield._keydir(str(source)).glob("*.tmp"))
    after = source.lstat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode) == (
        before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode,
    )
    assert source.read_bytes() == b"original stays"


def test_unsupported_staging_deletion_holds_before_another_orphan_can_grow(shield, tmp_path, monkeypatch):
    from angerona.core import shadow_cache_cleanup

    source = tmp_path / "document.txt"
    source.write_bytes(b"original stays")
    source.chmod(stat.S_IREAD)
    real_delete = shadow_cache_cleanup.delete_cache_file

    def failed_replace(*_args):
        raise PermissionError("inert publication refusal")

    monkeypatch.setattr(shadow_shield.os, "replace", failed_replace)
    with monkeypatch.context() as refusal:
        refusal.setattr(shadow_cache_cleanup, "delete_cache_file", lambda *_a, **_k: False)
        assert shield._cache_version(str(source))[0] == "failed"
        keydir = shield._keydir(str(source))
        staged = list(keydir.glob("*.tmp"))
        assert len(staged) == 1
        assert "partial cache cleanup unavailable" in shield._cache_storage_hold
        assert shield._cache_version(str(source)) == ("skipped", 0)
        assert list(keydir.glob("*.tmp")) == staged
    # Retire only the exact inert leftover, with its independent current identity.
    info = staged[0].lstat()
    assert real_delete(staged[0], expected_identity=shield._cache_file_identity(info))
    assert source.read_bytes() == b"original stays"


def test_failed_retention_holds_new_cache_writes_and_preserves_bound_version(shield, tmp_path, monkeypatch):
    from angerona.core import shadow_cache_cleanup

    source = tmp_path / "document.txt"
    source.write_bytes(b"original stays")
    keydir = shield._keydir(str(source))
    keydir.mkdir(parents=True)
    for number in range(shadow_shield.RETAIN_VERSIONS + 1):
        (keydir / f"{number}.bak").write_bytes(b"prior")
    before = {item.name: item.read_bytes() for item in keydir.iterdir()}

    def unavailable(*_args, **_kwargs):
        raise OSError("inert unsupported deletion")

    monkeypatch.setattr(shadow_cache_cleanup, "delete_cache_file", unavailable)
    shield._prune(keydir)
    assert shield._prune_errors == 1
    assert "cache retention unavailable" in shield._cache_storage_hold
    assert shield._cache_version(str(source)) == ("skipped", 0)
    assert {item.name: item.read_bytes() for item in keydir.iterdir()} == before


def test_one_cleanup_request_continues_bounded_progress_to_complete(shield, monkeypatch):
    outcomes = [
        dict(complete=False, removed_files=2, removed_bytes=10, removed_directories=1,
             reason="cleanup time bound reached; remaining copies preserved; run cleanup again"),
        dict(complete=False, removed_files=3, removed_bytes=20, removed_directories=1,
             reason="cleanup entry bound reached; remaining copies preserved; run cleanup again"),
        dict(complete=True, removed_files=1, removed_bytes=30, removed_directories=1,
             reason="recognized recovery copies removed"),
    ]
    previous = []

    def cleanup(_path, *, stopped):
        assert not stopped.is_set()
        status = shield.storage_status()
        assert status["cleanup_pending"]
        previous.append(status["cleanup_report"]["removed_files"])
        return outcomes.pop(0)

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    assert shield.request_cache_cleanup()
    shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    status = shield.storage_status()
    assert previous == [0, 2, 5]
    assert not status["cleanup_pending"] and not status["held"]
    assert status["cleanup_report"] == dict(complete=True, removed_files=6, removed_bytes=60,
                                             removed_directories=3, reason="recognized recovery copies removed")
    status["cleanup_report"]["removed_files"] = -1
    assert shield.storage_status()["cleanup_report"]["removed_files"] == 6


@pytest.mark.parametrize("reason,files,cancel", [
    ("unknown or unsafe entries preserved", 2, False),
    ("cleanup time bound reached; remaining copies preserved; run cleanup again", 0, False),
    ("cleanup entry bound reached; remaining copies preserved; run cleanup again", 2, True),
])
def test_cleanup_never_retries_unsafe_zero_progress_or_cancelled_pass(shield, monkeypatch, reason, files, cancel):
    calls = []

    def cleanup(_path, *, stopped):
        calls.append(1)
        if cancel:
            stopped.set()
        return dict(complete=False, removed_files=files, removed_bytes=files * 10,
                    removed_directories=0, reason=reason)

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    assert shield.request_cache_cleanup()
    shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    status = shield.storage_status()
    assert calls == [1]
    assert not status["cleanup_pending"] and status["held"]
    assert not status["cleanup_report"]["complete"]
    assert status["cleanup_report"]["removed_files"] == files
    if cancel:
        assert "cancelled" in status["cleanup_report"]["reason"]
    else:
        assert status["cleanup_report"]["reason"] == reason


def test_cleanup_overall_pass_budget_stops_positive_progress(shield, monkeypatch):
    calls = []
    monkeypatch.setattr(shadow_shield, "MAX_CLEANUP_PASSES", 2)

    def cleanup(_path, *, stopped):
        calls.append(1)
        return dict(complete=False, removed_files=1, removed_bytes=10, removed_directories=1,
                    reason="cleanup time bound reached; remaining copies preserved; run cleanup again")

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    assert shield.request_cache_cleanup()
    shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    status = shield.storage_status()
    assert calls == [1, 1]
    assert status["cleanup_report"]["removed_files"] == 2
    assert status["cleanup_report"]["removed_directories"] == 2
    assert "overall pass bound" in status["cleanup_report"]["reason"]
    assert status["held"] and not status["cleanup_pending"]


def test_primary_policy_and_limited_observation_advance_between_cleanup_passes(shield, tmp_path, monkeypatch):
    between = threading.Event()
    observed = threading.Event()
    completed_helper = threading.Event()
    calls = []
    notes = []
    source = tmp_path / "document.txt"
    source.write_bytes(b"source stays")

    def cleanup(_path, *, stopped):
        calls.append(threading.get_ident())
        assert not stopped.is_set()
        if len(calls) == 1:
            return dict(complete=False, removed_files=1, removed_bytes=10, removed_directories=1,
                        reason="cleanup time bound reached; remaining copies preserved; run cleanup again")
        assert observed.is_set()
        completed_helper.set()
        return dict(complete=True, removed_files=1, removed_bytes=10, removed_directories=1,
                    reason="recognized recovery copies removed")

    def interpass(_cancel):
        between.set()
        assert observed.wait(5), "primary could not observe maintenance between passes"

    def sleep(_seconds):
        status = shield.storage_status()
        notes.append((shield.health, shield.health_note, status))
        observed.set()
        assert completed_helper.wait(5)
        shield.stop()

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    monkeypatch.setattr(shield, "_cleanup_pass_pause", interpass)
    monkeypatch.setattr(shield, "_protected_files", lambda: pytest.fail("maintenance admitted a protected-file scan"))
    monkeypatch.setattr(shield, "sleep", sleep)
    assert shield.request_cache_cleanup()
    primary = threading.Thread(target=shield.run)
    try:
        assert between.wait(5)
        assert not shield.request_cache_cleanup()
        assert shield._cache_version(str(source)) == ("skipped", 0)
        assert not shield._inventory_cache()
        shield.configure_storage_policy(cache_enabled=True, vss_enabled=False,
                                        max_mib=128, min_free_mib=512)
        primary.start()
        assert observed.wait(5)
    finally:
        observed.set()
        completed_helper.set()
        if primary.ident is not None:
            primary.join(5)
        shield._cache_cleanup_cancel.set()
        shield._cache_cleanup_thread.join(5)
    assert not primary.is_alive() and not shield._cache_cleanup_thread.is_alive()
    assert len(calls) == 2 and calls[0] == calls[1]
    assert notes and notes[0][0] <= 50
    assert "coverage LIMITED" in notes[0][1] and "maintenance in progress" in notes[0][1]
    assert "cached=0" in notes[0][1]
    assert notes[0][2]["limit_bytes"] == 128 * 1024**2
    assert notes[0][2]["cleanup_pending"] and not notes[0][2]["inventory_complete"]
    assert shield.storage_status()["cleanup_report"]["complete"]
    assert source.read_bytes() == b"source stays"


def test_active_primary_stops_its_source_walk_when_cleanup_becomes_running(shield, monkeypatch):
    entered = threading.Event()
    visited = []

    def cleanup(_path, *, stopped):
        entered.set()
        assert stopped.wait(5)
        return dict(complete=False, removed_files=0, removed_bytes=0, reason="cancelled")

    def copy(path):
        visited.append(path)
        assert shield.request_cache_cleanup()
        assert entered.wait(5)
        return "cached", 1

    monkeypatch.setitem(sys.modules, "angerona.core.shadow_cache_cleanup", SimpleNamespace(cleanup_cache=cleanup))
    monkeypatch.setattr(shield, "_protected_files", lambda: iter(("one", "two", "three")))
    monkeypatch.setattr(shield, "_cache_version", copy)
    monkeypatch.setattr(shield, "sleep", lambda _: shield.stop())
    try:
        shield.run()
    finally:
        shield._cache_cleanup_cancel.set()
        shield._cache_cleanup_thread.join(5)
    assert not shield._cache_cleanup_thread.is_alive()
    assert visited == ["one"]
    assert "coverage LIMITED" in shield.health_note
