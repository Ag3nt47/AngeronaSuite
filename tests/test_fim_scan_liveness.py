from __future__ import annotations

import builtins
import threading

import pytest

from angerona.modules import file_integrity as fim


def _module(tmp_path, monkeypatch, *, missing_root=False):
    watched = tmp_path / "watched"
    watched.mkdir()
    roots = [str(watched)]
    if missing_root:
        roots.append(str(tmp_path / "missing-internal-root"))
    monkeypatch.setattr(fim, "watch_roots", lambda: roots)
    module = fim.FileIntegrityModule()
    module._baseline_path_override = tmp_path / "baseline.json"
    module._baseline_key_override = b"F" * 32
    return module, watched


def test_hash_cancels_between_chunks_without_retrying_or_returning_partial_digest(
    tmp_path, monkeypatch,
):
    module, watched = _module(tmp_path, monkeypatch)
    target = watched / "bounded.bin"
    target.write_bytes(b"x" * (3 * 65536))
    original_open = builtins.open
    reads = []
    opens = []

    class StopAfterRead:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.handle.close()

        def fileno(self):
            return self.handle.fileno()

        def read(self, size):
            chunk = self.handle.read(size)
            reads.append(len(chunk))
            module.stop()
            return chunk

    def open_file(path, mode="r", *args, **kwargs):
        handle = original_open(path, mode, *args, **kwargs)
        if str(path) == str(target) and mode == "rb":
            opens.append(str(path))
            return StopAfterRead(handle)
        return handle

    monkeypatch.setattr(builtins, "open", open_file)
    monkeypatch.setattr(module, "_handle_change_token", lambda _fd: 1)
    monkeypatch.setattr(module, "_handle_usn", lambda _fd: None)
    assert module._hash(str(target)) == ""
    assert reads == [65536]
    assert opens == [str(target)]


@pytest.mark.parametrize("replace_stop_token", [False, True])
def test_scan_cancels_inside_a_directory_and_preserves_incomplete_custody(
    tmp_path, monkeypatch, replace_stop_token,
):
    module, watched = _module(tmp_path, monkeypatch)
    for index in range(4):
        (watched / f"{index}.txt").write_text("synthetic", encoding="utf-8")
    observed = []
    original_stop = module.generation_stop_event()

    def interrupted_hash(path):
        observed.append(path)
        original_stop.set()
        if replace_stop_token:
            module._stop = threading.Event()
        return "a" * 64

    monkeypatch.setattr(module, "_hash", interrupted_hash)
    result = module._scan()
    assert len(observed) == 1
    assert not result  # Even the fake digest returned after stop is not admitted.
    assert module._last_scan_receipt["complete"] is False
    assert "stopped" in module._last_scan_receipt["reason"]
    assert module._baseline == {}
    assert not module._baseline_path.exists()


def test_real_progress_heartbeat_does_not_claim_verified_content_or_complete_scan(
    tmp_path, monkeypatch,
):
    module, _watched = _module(tmp_path, monkeypatch)
    module.status = "running"
    module._scan_work.stop_event = module.generation_stop_event()
    module._scan_work.progress = {"bytes": 0, "files": 0, "next_report": 0.0}
    original_receipt = dict(module._last_scan_receipt)
    module._report_scan_work(bytes_read=65536, files=1)
    assert module.first_cycle_complete
    assert module.health == 35
    assert "65536 bytes read" in module.health_note
    assert "verification pending" in module.health_note
    assert module._last_scan_receipt == original_receipt
    assert module._last_scan_receipt["complete"] is False
    assert module._pending_scan_custody is None
    assert module._baseline == {}


def test_missing_root_retries_full_scan_slowly_but_preserves_fast_driver_checks(
    tmp_path, monkeypatch,
):
    module, watched = _module(tmp_path, monkeypatch, missing_root=True)
    target = watched / "policy.txt"
    target.write_text("synthetic", encoding="utf-8")
    monkeypatch.setattr(fim, "_combat_intervals", lambda: (0.5, 1.0))
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "_publish_assurance_receipts", lambda: None)
    driver_checks = []
    monkeypatch.setattr(module, "_sweep_drivers", lambda: driver_checks.append(True))

    def driver_names():
        module._driver_collection_ok = True
        return set()

    monkeypatch.setattr(module, "_list_driver_names", driver_names)
    original_hash = module._hash
    hashed = []

    def count_hash(path):
        hashed.append(path)
        return original_hash(path)

    monkeypatch.setattr(module, "_hash", count_hash)
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        if sum(waits) >= 30:
            module.stop()

    monkeypatch.setattr(module, "sleep", sleep)
    module.run()
    assert hashed == [str(target)]
    assert waits == [0.5] * 60
    assert len(driver_checks) == 59
    assert module._scan_retry_floor == 30
    assert module.health == 35
    assert "full-scan retry in 30s" in module.health_note
    assert module._baseline == {}
    assert module._last_scan_receipt["complete"] is False
    assert not module._baseline_path.exists()


def test_incomplete_retry_is_bounded_and_complete_coverage_restores_normal_cadence(
    tmp_path, monkeypatch,
):
    module, _watched = _module(tmp_path, monkeypatch)
    module._last_scan_receipt = {"complete": False, "reason": "missing root"}
    intervals = []
    for _ in range(7):
        module._record_scan_outcome()
        intervals.append(module._scan_retry_floor)
    assert intervals == [30, 60, 120, 240, 300, 300, 300]
    module._last_scan_receipt = {"complete": True, "reason": "complete"}
    module._record_scan_outcome()
    assert module._scan_retry_floor == 0
    assert module._incomplete_scan_attempts == 0


def test_cancelled_initial_scan_does_not_publish_armed_state_or_adopt_baseline(
    tmp_path, monkeypatch,
):
    module, watched = _module(tmp_path, monkeypatch)
    (watched / "policy.txt").write_text("synthetic", encoding="utf-8")
    events = []
    monkeypatch.setattr(module, "emit", lambda message, *_args, **_kwargs: events.append(message))

    def cancel(_path):
        module.stop()
        return "a" * 64

    monkeypatch.setattr(module, "_hash", cancel)
    module.run()
    assert not any("FIM armed" in message for message in events)
    assert module._baseline == {}
    assert not module._baseline_path.exists()
