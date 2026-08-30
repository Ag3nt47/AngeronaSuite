from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from angerona.core import security_scan_center as scan_module
from angerona.core.security_scan_center import (
    ScanCancellationToken,
    SecurityScanCenter,
)
from angerona.gui.scan_center import ScanCenterPanel
from angerona.resilience import diagnostics
from angerona.resilience._selftest_environment import run_isolated_selftest
from angerona.resilience.manager import _OwnedSelfTestProcesses


def _scan_result(operation: str, status: str, *, errors=()) -> dict[str, object]:
    return {
        "operation": operation,
        "status": status,
        "supported": status != "unsupported",
        "executed": status not in {"rejected", "unsupported"},
        "findings": [],
        "errors": list(errors),
    }


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("completed", "completed", "completed"),
        ("completed", "limited", "limited"),
        ("completed", "unsupported", "partial"),
        ("completed", "rejected", "partial"),
        ("completed", "error", "error"),
        ("completed", "cancelled", "cancelled"),
        ("unsupported", "unsupported", "unsupported"),
    ],
)
def test_combined_scan_status_matrix(left: str, right: str, expected: str) -> None:
    result = ScanCenterPanel._merge_scan_results(
        _scan_result("angerona", left),
        _scan_result("defender", right, errors=("engine-refused",) if right == "error" else ()),
    )

    assert result["status"] == expected
    if left == right == "completed":
        assert result["status"] == "completed"
    else:
        assert result["status"] != "completed"
    statuses = result["summary"]["component_statuses"]
    assert [item["status"] for item in statuses] == [left, right]
    if right != "completed":
        assert statuses[1]["errors"]


def test_diagnostics_selftest_never_reroutes_a_concurrent_live_writer(
    tmp_path: Path,
) -> None:
    sentinel = tmp_path / "live-diagnostics"
    sentinel.mkdir()
    marker = sentinel / "must-survive.txt"
    marker.write_text("live", encoding="utf-8")
    previous = os.environ.get("ANGERONA_DIAG_DIR")
    os.environ["ANGERONA_DIAG_DIR"] = str(sentinel)
    observed: list[Path] = []
    writer_stop = threading.Event()

    def live_writer() -> None:
        while not writer_stop.is_set():
            observed.append(diagnostics.diag_dir())
            diagnostics.write_status("cycle26-live-writer")
            writer_stop.wait(0.01)

    writer = threading.Thread(target=live_writer)
    try:
        writer.start()
        ok, detail = diagnostics.self_test()
        assert ok, detail
        assert marker.read_text(encoding="utf-8") == "live"
        assert os.environ["ANGERONA_DIAG_DIR"] == str(sentinel)
        assert observed and set(observed) == {sentinel}
    finally:
        writer_stop.set()
        writer.join(timeout=5.0)
        if previous is None:
            os.environ.pop("ANGERONA_DIAG_DIR", None)
        else:
            os.environ["ANGERONA_DIAG_DIR"] = previous


def test_selftest_variable_callback_failure_still_removes_owned_root() -> None:
    captured: list[Path] = []

    def fail(root: Path) -> dict[str, str]:
        captured.append(root)
        raise RuntimeError("deterministic variable failure")

    with pytest.raises(RuntimeError, match="deterministic variable failure"):
        run_isolated_selftest("diagnostics", "c26_callback_", fail)

    assert captured and not captured[0].exists()


def test_manager_selftest_custody_reaps_only_its_exact_child_chain() -> None:
    marker = "angerona-cycle26-owned-process"
    child_script = "import time; time.sleep(30)"
    parent_script = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); "
        "time.sleep(30)"
    )
    owned = subprocess.Popen(
        [sys.executable, "-c", parent_script, child_script, marker],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    unrelated = subprocess.Popen(
        [sys.executable, "-c", child_script, "not-owned"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    custody = _OwnedSelfTestProcesses(marker)
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            custody.capture(owned)
            if len(custody._identities) >= 2:
                break
            time.sleep(0.05)
        assert len(custody._identities) >= 2
        try:
            raise RuntimeError("forced manager self-test failure")
        finally:
            custody.reap()
        assert False, "forced exception must propagate"
    except RuntimeError as exc:
        assert "forced manager" in str(exc)
        assert owned.poll() is not None
        assert unrelated.poll() is None
    finally:
        custody.reap()
        if unrelated.poll() is None:
            unrelated.terminate()
            try:
                unrelated.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                unrelated.kill()
                unrelated.wait(timeout=2.0)


def _local_center(**kwargs) -> SecurityScanCenter:
    return SecurityScanCenter(
        yara_module=object(),
        usb_authorizer=lambda _target: (True, "test-approved"),
        **kwargs,
    )


def test_scan_rejects_same_volume_hardlink_before_content_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected"
    selected.mkdir()
    outside = tmp_path / "outside-secret.bin"
    outside.write_bytes(b"outside-object-sentinel")
    alias = selected / "inside-alias.bin"
    try:
        os.link(outside, alias)
    except OSError:
        pytest.skip("same-volume hard links are unavailable for this test account")
    reads: list[int] = []
    real_read = scan_module.os.read

    def observed_read(descriptor: int, count: int) -> bytes:
        reads.append(count)
        return real_read(descriptor, count)

    monkeypatch.setattr(scan_module.os, "read", observed_read)
    result = _local_center().scan_path(selected)

    assert result.status == "limited"
    assert result.metrics["files_scanned"] == 0
    assert result.metrics["unsafe_scope_skips"] == 1
    assert reads == []


def test_empty_wide_tree_is_bounded_by_directory_entry_budget(tmp_path: Path) -> None:
    selected = tmp_path / "wide-empty"
    selected.mkdir()
    for index in range(12):
        (selected / f"empty-{index:02d}").mkdir()

    result = _local_center(
        max_directory_entries=4,
        max_directories=100,
    ).scan_path(selected)

    assert result.status == "limited"
    assert result.metrics["files_scanned"] == 0
    assert result.metrics["directory_entries_seen"] == 4
    assert result.metrics["traversal_limit_reason"] == "directory-entry-limit"


def test_directory_queue_is_bounded_without_any_regular_files(tmp_path: Path) -> None:
    selected = tmp_path / "deep-empty"
    selected.mkdir()
    cursor = selected
    for index in range(8):
        cursor = cursor / f"level-{index}"
        cursor.mkdir()

    result = _local_center(
        max_directory_entries=100,
        max_directories=3,
    ).scan_path(selected)

    assert result.status == "limited"
    assert result.metrics["files_scanned"] == 0
    assert result.metrics["directories_discovered"] == 3
    assert result.metrics["traversal_limit_reason"] == "directory-queue-limit"


def test_slow_directory_iterator_is_timed_out_before_entry_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "slow-empty"
    selected.mkdir()
    clock = [0.0]

    class SlowEntries:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            clock[0] = 2.0
            return object()

    monkeypatch.setattr(scan_module.os, "scandir", lambda _path: SlowEntries())
    result = _local_center(
        max_duration_seconds=1.0,
        monotonic=lambda: clock[0],
    ).scan_path(selected)

    assert result.status == "limited"
    assert result.metrics["files_scanned"] == 0
    assert result.metrics["timed_out"] is True
    assert result.metrics["directory_entries_seen"] == 0


def test_empty_tree_traversal_observes_cancellation_after_slow_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "cancel-empty"
    selected.mkdir()
    token = ScanCancellationToken()

    class CancellingEntries:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            token.cancel()
            return object()

    monkeypatch.setattr(scan_module.os, "scandir", lambda _path: CancellingEntries())
    result = _local_center().scan_path(selected, cancellation=token)

    assert result.status == "cancelled"
    assert result.metrics["files_scanned"] == 0
    assert result.metrics["directory_entries_seen"] == 0
