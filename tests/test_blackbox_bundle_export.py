"""Real Qt export ownership with inert sources; no host collection/network."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from types import SimpleNamespace
import zipfile

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from shiboken6 import isValid

import blackbox_recorder as blackbox


def _pump(app, predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert predicate()


def _deferred():
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


@pytest.fixture
def sources(monkeypatch, tmp_path):
    paths = {}
    for constant, name in (
        ("NOT_RESPONDING", "not_responding.log"), ("SELFTEST_FAILURES", "selftest_failures.json"),
        ("CRASH_LOG", "crash.log"), ("STATUS_JSON", "status.json"),
        ("FLOW_METRICS", "flow_metrics.json"), ("SETTINGS_JSON", "settings.json"),
        ("ENV_FILE", ".env"),
    ):
        path = tmp_path / name
        path.write_bytes(b"controlled diagnostic\n")
        monkeypatch.setattr(blackbox, constant, path)
        paths[constant] = path
    paths["SETTINGS_JSON"].write_text(json.dumps({
        "live_debug_enabled": True, "spyware_memory_enabled": False,
        "spyware_beacon_signal": "SECRET_BAD_BOOL", "api_key": "SECRET_KEY_VALUE",
        "spyware_research_urls": ["https://private.example/?token=SECRET_QUERY"],
        "endpoint": "SECRET_ENDPOINT", "custom": {"password": "SECRET_NESTED"},
    }), encoding="utf8")
    paths["ENV_FILE"].write_bytes(b"SECRET_ENV_ONLY=not_for_zip\n")
    crash = tmp_path / "crash_snapshots"
    crash.mkdir()
    monkeypatch.setattr(blackbox, "CRASH_SNAP_DIR", crash)
    monkeypatch.setattr(blackbox, "ARCHIVE_DIR", tmp_path)
    paths["CRASH_SNAP_DIR"] = crash
    return paths


@pytest.fixture
def window(monkeypatch, sources, tmp_path):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    monkeypatch.setattr(blackbox, "_HAS_CHARTS", False)
    monkeypatch.setattr(blackbox.BlackBoxWindow, "_start_workers", lambda self: None)
    monkeypatch.setattr(blackbox.SoarEventsTab, "_read_records", staticmethod(lambda: []))
    monkeypatch.setattr(blackbox.FirewallTab, "_read_rules", staticmethod(lambda: []))
    monkeypatch.setattr(blackbox, "find_angerona_pid", lambda: pytest.fail("No discovery during export"))
    monkeypatch.setattr(blackbox.psutil, "process_iter", lambda *a, **k: pytest.fail("No host enumeration"))
    dialogs, notices = [], []
    def choose(*args):
        dialogs.append(args)
        return str(tmp_path / f"bundle-{len(dialogs)}.zip"), ""
    monkeypatch.setattr(blackbox.QFileDialog, "getSaveFileName", choose)
    monkeypatch.setattr(blackbox.QMessageBox, "information", lambda *a: notices.append(("info", a)))
    monkeypatch.setattr(blackbox.QMessageBox, "warning", lambda *a: notices.append(("warning", a)))
    win = blackbox.BlackBoxWindow()
    win._test_dialogs = dialogs
    win._test_notices = notices
    yield app, win
    # Test failures must still retire every owned worker before deleting Qt.
    if isValid(win):
        win.stop_workers(timeout_ms=0)
        assert win.stop_workers(timeout_ms=6000)
        win.close()
        win.deleteLater()
    app.processEvents()
    _deferred()


def _read_bundle(path):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        return {name: archive.read(name) for name in archive.namelist()}


def test_bundle_runs_in_worker_coalesces_clicks_and_deletes_retired_worker(window, monkeypatch, sources):
    app, win = window
    entered, release = threading.Event(), threading.Event()
    threads, beats = [], []
    real_read = blackbox._BundleBuilder.read_source
    def held_read(self, *args, **kwargs):
        if not entered.is_set():
            threads.append(threading.get_ident())
            entered.set()
            assert release.wait(5)
        return real_read(self, *args, **kwargs)
    monkeypatch.setattr(blackbox._BundleBuilder, "read_source", held_read)
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: beats.append(1))
    timer.start()
    before = {key: (path.read_bytes(), path.stat().st_mtime_ns)
              for key, path in sources.items() if path.is_file()}
    try:
        win.on_export_bundle()
        worker = win._bundle_worker
        destination = worker.out
        assert entered.wait(2)
        for _ in range(8):
            win.on_export_bundle()
        _pump(app, lambda: len(beats) >= 4)
        assert worker is win._bundle_worker and worker.isRunning()
        assert len(win._test_dialogs) == 1 and threads != [threading.get_ident()]
        assert not win.btn_export.isEnabled() and win.btn_cancel_bundle.isEnabled()
        release.set()
        _pump(app, lambda: win._bundle_worker is None)
        assert not isValid(worker) or worker.wait(0)
        assert win.btn_export.isEnabled() and not win.btn_cancel_bundle.isEnabled()
        assert len(win._test_notices) == 1 and win._test_notices[0][0] == "info"
        data = _read_bundle(destination)
        assert "manifest.json" in data and "ui_snapshot.json" in data
        assert before == {key: (path.read_bytes(), path.stat().st_mtime_ns)
                          for key, path in sources.items() if path.is_file()}
        _deferred()
        assert not isValid(worker)
        win._bundle_retired(worker)  # A late callback must ignore deleted Qt objects.
        assert len(win._test_notices) == 1
    finally:
        release.set()
        timer.stop()
        if "worker" in locals() and isValid(worker):
            worker.stop()
            assert worker.wait(5000)


def test_bundle_capture_selects_tail_before_copy_and_does_not_call_snapshot_text(window, monkeypatch):
    _app, win = window
    text = "prefix " + "x" * (blackbox.BUNDLE_GUI_CHARS * 4) + " END☃"
    win.tab_logs.console.setPlainText(text)
    monkeypatch.setattr(win.tab_logs.console, "toPlainText", lambda: pytest.fail("Full widget copy"))
    for name in ("tab_logs", "tab_host", "tab_health", "tab_threads", "tab_mem", "tab_config", "tab_soar", "tab_firewall", "tab_live_debug"):
        monkeypatch.setattr(getattr(win, name), "snapshot_text", lambda: pytest.fail("Unbounded legacy snapshot"))
    win.tab_threads.latest = [{"name": "A" * 100000, "where": "B" * 100000}] * 1000
    capture = win._capture_bundle()
    assert capture["console_tail"].endswith(" END☃")
    assert len(capture["console_tail"]) <= 16 * 1024
    assert len(capture["views"]["thread_state"]) <= 64
    assert capture["omitted"] > 0
    assert len(blackbox._bundle_json(capture)) <= 256 * 1024
    win.tab_threads.latest[0]["name"] = "MUTATED"
    assert capture["views"]["thread_state"][0]["name"] != "MUTATED"


def test_bundle_settings_allowlist_env_hash_and_explicit_privacy(sources, tmp_path):
    result = blackbox._BundleBuilder(lambda: False).build(tmp_path / "private.zip", {"omitted": 0})
    assert result["published"] and result["status"] == "created-with-gaps"
    data = _read_bundle(tmp_path / "private.zip")
    flags = json.loads(data["settings.sanitized.json"])
    assert flags["flags"] == {"live_debug_enabled": True, "spyware_memory_enabled": False}
    assert flags["omitted_top_level_fields"] == 5
    assert "settings.json" not in data and ".env" not in data
    assert b"SECRET_" not in b"".join(data.values())
    manifest = json.loads(data["manifest.json"])
    assert manifest["env_sha256"] == hashlib.sha256(sources["ENV_FILE"].read_bytes()).hexdigest()
    assert manifest["advisory_only"] and manifest["private_export"]
    assert "private data" in manifest["privacy"] and "Originals are unchanged" in manifest["privacy"]


@pytest.mark.parametrize("raw", [b'{"live_debug_enabled":true,"live_debug_enabled":false}', b'[]', b'{broken'])
def test_bundle_invalid_settings_never_copies_raw_values(sources, tmp_path, raw):
    sources["SETTINGS_JSON"].write_bytes(raw)
    result = blackbox._BundleBuilder(lambda: False).build(tmp_path / "invalid.zip", {"omitted": 0})
    assert result["published"]
    data = _read_bundle(tmp_path / "invalid.zip")
    assert "settings.sanitized.json" not in data
    assert any(row["reason"] == "invalid-settings-omitted" for row in json.loads(data["manifest.json"])["gaps"])


def test_bundle_chunk_and_aggregate_limits_are_enforced(sources, tmp_path, monkeypatch):
    monkeypatch.setattr(blackbox, "BUNDLE_CHUNK_BYTES", 1024)
    monkeypatch.setattr(blackbox, "BUNDLE_TOTAL_BYTES", 80 * 1024)
    monkeypatch.setattr(blackbox, "BUNDLE_READ_BYTES", 10 * 1024)
    monkeypatch.setattr(blackbox, "BUNDLE_FILE_BYTES", 8 * 1024)
    for key in ("NOT_RESPONDING", "SELFTEST_FAILURES", "CRASH_LOG", "STATUS_JSON", "FLOW_METRICS"):
        sources[key].write_bytes(b"d" * (12 * 1024))
    sizes = []
    fdopen = blackbox.os.fdopen
    class ReadProbe:
        def __init__(self, wrapped):
            self.wrapped = wrapped
        def __enter__(self):
            self.wrapped.__enter__()
            return self
        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)
        def __getattr__(self, name):
            return getattr(self.wrapped, name)
        def read(self, size):
            sizes.append(size)
            assert 0 < size <= 1024
            return self.wrapped.read(size)
    monkeypatch.setattr(blackbox.os, "fdopen", lambda fd, mode: ReadProbe(fdopen(fd, mode)) if mode == "rb" else fdopen(fd, mode))
    builder = blackbox._BundleBuilder(lambda: False)
    result = builder.build(tmp_path / "bounded.zip", {"omitted": 1})
    assert result["published"] and result["gap_count"] > 0
    assert sizes and builder.read_left >= 0 and builder.write_left >= 0
    with zipfile.ZipFile(tmp_path / "bounded.zip") as archive:
        assert sum(item.file_size for item in archive.infolist()) <= blackbox.BUNDLE_TOTAL_BYTES
        assert len(archive.infolist()) <= blackbox.BUNDLE_MEMBER_LIMIT
        manifest = json.loads(archive.read("manifest.json"))
        assert any("limit" in row["reason"] for row in manifest["gaps"])


@pytest.mark.parametrize("entry_count, regular_count", [(40, 40), (80, 0)])
def test_bundle_crash_file_and_entry_counts_are_bounded(sources, tmp_path, monkeypatch, entry_count, regular_count):
    directory = sources["CRASH_SNAP_DIR"]
    for index in range(entry_count):
        path = directory / str(index)
        if index < regular_count:
            path.write_bytes(b"fixture")
        else:
            path.mkdir()
    scandir, scanned = blackbox.os.scandir, []
    class ScanProbe:
        def __init__(self, wrapped):
            self.wrapped = wrapped
        def __enter__(self):
            self.wrapped.__enter__()
            return self
        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)
        def __iter__(self):
            return self
        def __next__(self):
            entry = next(self.wrapped)
            scanned.append(entry.name)
            return entry
    monkeypatch.setattr(blackbox.os, "scandir", lambda path: ScanProbe(scandir(path)))
    result = blackbox._BundleBuilder(lambda: False).build(tmp_path / "counts.zip", {"omitted": 0})
    assert result["published"]
    data = _read_bundle(tmp_path / "counts.zip")
    assert sum(name.startswith("crash_snapshots/") for name in data) == min(regular_count, blackbox.BUNDLE_CRASH_FILES)
    scan_limit = blackbox.BUNDLE_CRASH_FILES if regular_count else blackbox.BUNDLE_SCAN_ENTRIES
    assert len(scanned) == min(entry_count, scan_limit)
    manifest = json.loads(data["manifest.json"])
    reasons = {row["reason"] for row in manifest["gaps"]}
    assert "file-count-limit-remainder-unknown" in reasons or "entry-scan-limit-remainder-unknown" in reasons
    assert len(manifest["gaps"]) <= 64 and manifest["omitted_gap_count"] == 0
    if not regular_count:
        repeated = [row for row in manifest["gaps"] if row["source"] == "crash_snapshots"
                    and row["reason"] == "nonregular-entry-omitted"]
        assert len(repeated) == 1 and repeated[0]["count"] == blackbox.BUNDLE_SCAN_ENTRIES
    assert result["gap_count"] == sum(row.get("count", 1) for row in manifest["gaps"])


def test_bundle_growing_file_is_reported_and_read_does_not_follow_append(sources, tmp_path, monkeypatch):
    source = sources["NOT_RESPONDING"]
    original = b"original snapshot"
    source.write_bytes(original)
    wanted = (source.stat().st_dev, source.stat().st_ino)
    fdopen = blackbox.os.fdopen
    mutated = []
    class GrowingRead:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            self.stream.__enter__()
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def __getattr__(self, name):
            return getattr(self.stream, name)
        def read(self, size):
            data = self.stream.read(size)
            if not mutated:
                with source.open("ab") as output:
                    output.write(b"append" * 10000)
                mutated.append(True)
            return data
    def wrap(fd, mode):
        stream = fdopen(fd, mode)
        info = os.fstat(fd)
        return GrowingRead(stream) if mode == "rb" and (info.st_dev, info.st_ino) == wanted else stream
    monkeypatch.setattr(blackbox.os, "fdopen", wrap)
    result = blackbox._BundleBuilder(lambda: False).build(tmp_path / "growth.zip", {"omitted": 0})
    assert result["published"] and mutated
    data = _read_bundle(tmp_path / "growth.zip")
    assert data["diagnostics/not_responding.log.snapshot"] == original
    assert any(row["reason"] == "source-changed-during-read" for row in json.loads(data["manifest.json"])["gaps"])


def test_bundle_existing_destination_is_unchanged_and_partial_is_cleaned(sources, tmp_path):
    out = tmp_path / "existing.zip"
    out.write_bytes(b"existing user bytes")
    before = (out.read_bytes(), out.stat().st_mtime_ns)
    result = blackbox._BundleBuilder(lambda: False).build(out, {"omitted": 0})
    assert not result["published"] and result["error_type"] == "FileExistsError"
    assert (out.read_bytes(), out.stat().st_mtime_ns) == before
    assert list(tmp_path.glob(".Angerona_bundle_*.zip.partial")) == []


@pytest.mark.parametrize("mode", ["cancel", "deadline", "compress-failure", "publish-failure"])
def test_bundle_cancel_and_failures_never_publish_partial(sources, tmp_path, monkeypatch, mode):
    builder = blackbox._BundleBuilder(lambda: mode == "cancel")
    if mode == "deadline":
        builder.deadline = time.monotonic() - 1
    if mode == "compress-failure":
        def fail(*args):
            raise OSError("inert write failure")
        monkeypatch.setattr(builder, "populate", fail)
    if mode == "publish-failure":
        def fail(*args, **kwargs):
            raise OSError("inert atomic publication unsupported")
        monkeypatch.setattr(blackbox.os, "link", fail)
    out = tmp_path / "failed.zip"
    result = builder.build(out, {"omitted": 0})
    assert not result["published"] and not out.exists()
    assert result["status"] == {"cancel": "cancelled", "deadline": "deadline-exceeded"}.get(mode, "failed")
    assert list(tmp_path.glob(".Angerona_bundle_*.zip.partial")) == []


def test_bundle_close_requests_cancellation_without_blocking_or_destroying_thread(window, monkeypatch):
    app, win = window
    entered, release = threading.Event(), threading.Event()
    beats, closed = [], []
    read = blackbox._BundleBuilder.read_source
    def held(self, *args, **kwargs):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return read(self, *args, **kwargs)
    monkeypatch.setattr(blackbox._BundleBuilder, "read_source", held)
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: beats.append(1))
    timer.start()
    win.setAttribute(Qt.WA_DeleteOnClose)
    win.close_completed.connect(lambda: closed.append({
        "retired": win._bundle_worker.wait(0), "result": win._bundle_worker.result,
    }))
    win.show()
    try:
        win.on_export_bundle()
        worker = win._bundle_worker
        destination = worker.out
        notices = win._test_notices
        assert entered.wait(2)
        began = time.monotonic()
        win.close()
        assert time.monotonic() - began < 0.5
        assert worker.isRunning() and isValid(win) and not closed
        assert worker in win._shutdown_threads
        assert not win.btn_export.isEnabled()
        _pump(app, lambda: len(beats) >= 4)
        assert worker.isRunning() and not closed
        release.set()
        _pump(app, lambda: bool(closed))
        assert closed[0]["retired"] and closed[0]["result"]["status"] == "cancelled"
        assert not destination.exists() and notices == []
    finally:
        release.set()
        timer.stop()
        if "worker" in locals() and isValid(worker):
            assert worker.wait(5000)


def test_bundle_start_failure_recovers_admission_without_leaking_thread(window, monkeypatch):
    app, win = window
    original = blackbox._BundleExportWorker
    workers = []
    class StartFailure(original):
        def __init__(self, *args):
            super().__init__(*args)
            workers.append(self)
        def start(self):
            raise RuntimeError("inert start refusal")
    monkeypatch.setattr(blackbox, "_BundleExportWorker", StartFailure)
    win.on_export_bundle()
    _pump(app, lambda: win._bundle_worker is None)
    assert win.btn_export.isEnabled() and not win.btn_cancel_bundle.isEnabled()
    assert workers and (not isValid(workers[0]) or workers[0].wait(0))
    assert len(win._test_notices) == 1 and win._test_notices[0][0] == "warning"
    _deferred()
    assert not isValid(workers[0])


def test_bundle_cancel_button_keeps_admission_until_worker_retires(window, monkeypatch):
    app, win = window
    entered, release = threading.Event(), threading.Event()
    read = blackbox._BundleBuilder.read_source
    def held(self, *args, **kwargs):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return read(self, *args, **kwargs)
    monkeypatch.setattr(blackbox._BundleBuilder, "read_source", held)
    try:
        win.on_export_bundle()
        worker = win._bundle_worker
        destination = worker.out
        assert entered.wait(2)
        win.btn_cancel_bundle.click()
        win.on_export_bundle()
        assert worker.isRunning() and win._bundle_worker is worker
        assert len(win._test_dialogs) == 1 and not win.btn_cancel_bundle.isEnabled()
        release.set()
        _pump(app, lambda: win._bundle_worker is None)
        assert not isValid(worker) or worker.wait(0)
        assert not destination.exists() and win._test_notices == []
        assert win.btn_export.isEnabled()
    finally:
        release.set()
        if "worker" in locals() and isValid(worker):
            assert worker.wait(5000)


@pytest.mark.parametrize("constant, limit_name, member", [
    ("ENV_FILE", "BUNDLE_ENV_BYTES", "env_sha256"),
    ("SETTINGS_JSON", "BUNDLE_SETTINGS_BYTES", "settings.sanitized.json"),
])
def test_bundle_oversized_private_config_is_omitted_not_prefix_hashed_or_copied(
        sources, tmp_path, monkeypatch, constant, limit_name, member):
    monkeypatch.setattr(blackbox, limit_name, 32)
    sources[constant].write_bytes(b"SECRET_CONFIG" * 16)
    result = blackbox._BundleBuilder(lambda: False).build(tmp_path / "oversized.zip", {"omitted": 0})
    assert result["published"]
    data = _read_bundle(tmp_path / "oversized.zip")
    manifest = json.loads(data["manifest.json"])
    assert member not in data and member not in manifest
    assert b"SECRET_CONFIG" not in b"".join(data.values())
    assert any(row["reason"] == "complete-source-exceeds-limit" for row in manifest["gaps"])


def test_bundle_source_identity_change_is_omitted(sources, tmp_path, monkeypatch):
    source = sources["NOT_RESPONDING"]
    source.write_bytes(b"MUST_NOT_EXPORT_CHANGED_IDENTITY")
    wanted = (source.stat().st_dev, source.stat().st_ino)
    fstat = blackbox.os.fstat
    def changed(fd):
        info = fstat(fd)
        if (info.st_dev, info.st_ino) == wanted:
            return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino + 1)
        return info
    monkeypatch.setattr(blackbox.os, "fstat", changed)
    result = blackbox._BundleBuilder(lambda: False).build(tmp_path / "identity.zip", {"omitted": 0})
    assert result["published"]
    data = _read_bundle(tmp_path / "identity.zip")
    assert "diagnostics/not_responding.log.snapshot" not in data
    assert b"MUST_NOT_EXPORT_CHANGED_IDENTITY" not in b"".join(data.values())
    assert any(row["reason"] == "source-identity-changed-omitted" for row in json.loads(data["manifest.json"])["gaps"])


def test_bundle_partial_identity_mismatch_holds_cleanup_instead_of_unlinking(sources, tmp_path, monkeypatch):
    lstat = blackbox.Path.lstat
    def changed(path, *args, **kwargs):
        info = lstat(path, *args, **kwargs)
        if path.name.startswith(".Angerona_bundle_"):
            return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino + 1)
        return info
    monkeypatch.setattr(blackbox.Path, "lstat", changed)
    out = tmp_path / "identity-held.zip"
    result = blackbox._BundleBuilder(lambda: False).build(out, {"omitted": 0})
    assert not result["published"] and result["cleanup_gap"] and not out.exists()
    assert len(list(tmp_path.glob(".Angerona_bundle_*.zip.partial"))) == 1


def test_bundle_dialog_reentrancy_is_held_and_cancel_restores_button(window, monkeypatch):
    _app, win = window
    dialogs = []
    def choose(*args):
        dialogs.append(True)
        win.on_export_bundle()
        return "", ""
    monkeypatch.setattr(blackbox.QFileDialog, "getSaveFileName", choose)
    win.on_export_bundle()
    assert dialogs == [True] and win._bundle_worker is None
    assert win.btn_export.isEnabled() and not win.btn_cancel_bundle.isEnabled()


def test_bundle_raw_diagnostics_remain_private_copies_not_a_redaction_claim(sources, tmp_path):
    original = b"password=PRIVATE_DIAGNOSTIC_ORIGINAL\n"
    sources["CRASH_LOG"].write_bytes(original)
    result = blackbox._BundleBuilder(lambda: False).build(tmp_path / "raw-private.zip", {"omitted": 0})
    assert result["published"]
    data = _read_bundle(tmp_path / "raw-private.zip")
    assert data["diagnostics/crash.log.snapshot"] == original
    assert sources["CRASH_LOG"].read_bytes() == original
    assert "Raw diagnostics and UI copies can contain private data" in json.loads(data["manifest.json"])["privacy"]


def test_bundle_capture_bounds_values_without_coercing_untrusted_objects():
    class Unexpected:
        def __str__(self):
            pytest.fail("Untrusted object coerced")
    capture = blackbox._BundleCapture()
    assert capture.copy(Unexpected()) is None
    assert capture.copy(1 << 80) is None
    assert capture.copy(float("nan")) is None
    assert capture.omitted == 3
    capture.chars = 2
    assert capture.copy({"long_key": "value"}) == {}
    assert capture.chars >= 0


@pytest.mark.parametrize("published", [True, False], ids=["published", "unpublished"])
@pytest.mark.parametrize("cleanup_failure", ["unlink", "identity"])
def test_bundle_saturated_gap_list_keeps_cleanup_warning_on_both_result_paths(
        sources, tmp_path, monkeypatch, published, cleanup_failure):
    # Keep normal fixture sources complete so the only overflow is the late
    # owned-partial cleanup fault after all64 source gap slots are occupied.
    sources["SETTINGS_JSON"].write_text("{}", encoding="utf8")
    originals = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                 for path in sources.values() if path.is_file()}
    builder = blackbox._BundleBuilder(lambda: False)
    for index in range(64):
        builder.gap(f"prefilled-source-{index}", "inert-source-gap")
    original_gaps = [dict(row) for row in builder.manifest["gaps"]]
    assert len(original_gaps) == 64 and builder.manifest["omitted_gap_count"] == 0

    out = tmp_path / "saturated-gaps.zip"
    original_output = None
    if not published:
        out.write_bytes(b"existing user output must survive")
        original_output = out.read_bytes(), out.stat().st_mtime_ns
    lstat, unlink = blackbox.Path.lstat, blackbox.Path.unlink
    partial_checks, cleanup_unlinks = [], []
    def observed_identity(path, *args, **kwargs):
        info = lstat(path, *args, **kwargs)
        if path.name.startswith(".Angerona_bundle_"):
            partial_checks.append(path)
            if cleanup_failure == "identity" and len(partial_checks) == 2:
                return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev,
                                       st_ino=info.st_ino + 1)
        return info
    def cleanup(path, *args, **kwargs):
        if path.name.startswith(".Angerona_bundle_"):
            cleanup_unlinks.append(path)
            if cleanup_failure == "unlink":
                raise PermissionError("inert owned-partial unlink refusal")
        return unlink(path, *args, **kwargs)
    monkeypatch.setattr(blackbox.Path, "lstat", observed_identity)
    monkeypatch.setattr(blackbox.Path, "unlink", cleanup)

    result = builder.build(out, {"omitted": 0})
    assert result["published"] is published and result["cleanup_gap"] is True
    assert result["gap_count"] == 65
    assert builder.manifest["gaps"] == original_gaps
    assert builder.manifest["omitted_gap_count"] == 1
    assert not any(row["source"] == "partial_archive" for row in builder.manifest["gaps"])
    assert len(partial_checks) == 2
    assert len(cleanup_unlinks) == (1 if cleanup_failure == "unlink" else 0)
    partials = list(tmp_path.glob(".Angerona_bundle_*.zip.partial"))
    assert len(partials) == 1  # Failed/held cleanup must remain visible, never pretend success.
    partial_data = _read_bundle(partials[0])
    archive_manifest = json.loads(partial_data["manifest.json"])
    assert archive_manifest["gaps"] == original_gaps
    assert archive_manifest["omitted_gap_count"] == 0  # Finalized before the cleanup fault.
    if published:
        assert result["status"] == "created-with-gaps"
        assert _read_bundle(out) == partial_data
        assert out.read_bytes() == partials[0].read_bytes()
    else:
        assert result["status"] == "failed" and result["error_type"] == "FileExistsError"
        assert (out.read_bytes(), out.stat().st_mtime_ns) == original_output
    for path, before in originals.items():
        assert (path.read_bytes(), path.stat().st_mtime_ns) == before
