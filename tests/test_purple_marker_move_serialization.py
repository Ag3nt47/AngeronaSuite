"""A marker move cannot split a whole-target lease scan."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from angerona.modules.purple_guard import _validation_target_markers_safe


@pytest.mark.parametrize("serialized", [False, True])
def test_marker_rename_cannot_occur_between_enumeration_and_identity_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, serialized: bool,
) -> None:
    marker = tmp_path / "_redteam_inert_probe.txt"
    marker.write_bytes(b"inert drill marker")
    moved_dir = tmp_path / "quarantine"
    moved_dir.mkdir()
    destination = moved_dir / marker.name
    info = marker.stat(follow_symlinks=False)
    enrolled = {
        "device": info.st_dev, "inode": info.st_ino,
        "size": info.st_size, "mtime_ns": info.st_mtime_ns,
    }
    move_lock = threading.RLock()
    at_identity_check = threading.Event()
    allow_identity_check = threading.Event()
    mover_attempted = threading.Event()
    mover_done = threading.Event()
    original_stat = Path.stat

    def paused_stat(path: Path, *args: object, **kwargs: object):
        if path == marker and threading.current_thread().name == "marker-scanner":
            at_identity_check.set()
            if not allow_identity_check.wait(3):
                raise TimeoutError("scanner identity barrier did not release")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", paused_stat)
    results: list[bool] = []

    def scan() -> None:
        results.append(_validation_target_markers_safe(
            tmp_path,
            exclusive_handoffs={os.path.normcase(str(marker)): enrolled},
            move_lock=move_lock if serialized else None,
        ))

    def move() -> None:
        mover_attempted.set()
        with move_lock:
            os.replace(marker, destination)
        mover_done.set()

    scanner = threading.Thread(target=scan, name="marker-scanner")
    mover = threading.Thread(target=move, name="marker-mover")
    scanner.start()
    try:
        assert at_identity_check.wait(3)
        mover.start()
        assert mover_attempted.wait(3)
        if serialized:
            assert not mover_done.wait(0.05)
        else:
            assert mover_done.wait(3)
    finally:
        allow_identity_check.set()
        scanner.join(timeout=3)
        if mover.ident is not None:
            mover.join(timeout=3)

    assert not scanner.is_alive() and not mover.is_alive()
    assert mover_done.is_set()
    assert results == [serialized]
    assert not marker.exists() and destination.read_bytes() == b"inert drill marker"
