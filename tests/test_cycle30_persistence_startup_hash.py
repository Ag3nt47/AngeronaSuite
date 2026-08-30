from __future__ import annotations

import os

from angerona.modules.persistence_sweep import PersistenceSweepModule


def test_same_size_and_mtime_content_replacement_changes_startup_identity(tmp_path) -> None:
    startup = tmp_path / "startup.exe"
    startup.write_bytes(b"A" * 4096)
    before_stat = startup.stat()
    before, consumed, verified = PersistenceSweepModule._startup_file_record(
        str(startup), budget_bytes=8192
    )
    assert verified
    assert consumed == 4096

    startup.write_bytes(b"B" * 4096)
    os.utime(startup, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
    after, _, verified_after = PersistenceSweepModule._startup_file_record(
        str(startup), budget_bytes=8192
    )

    assert verified_after
    assert before["size"] == after["size"]
    assert before["mtime_ns"] == after["mtime_ns"]
    assert before["sha256"] != after["sha256"]


def test_oversized_startup_file_is_explicitly_pending_not_metadata_verified(
    tmp_path,
) -> None:
    startup = tmp_path / "oversized.exe"
    startup.write_bytes(b"payload")

    record, consumed, verified = PersistenceSweepModule._startup_file_record(
        str(startup), budget_bytes=3
    )

    assert not verified
    assert consumed == 0
    assert record["sha256"] == ""
    assert record["integrity_status"] == "pending-hash-budget"
    assert record["device"] == startup.stat().st_dev
    assert record["inode"] == startup.stat().st_ino


def test_post_hash_path_identity_swap_fails_closed(tmp_path, monkeypatch) -> None:
    startup = tmp_path / "startup.exe"
    replacement = tmp_path / "replacement.exe"
    startup.write_bytes(b"trusted")
    replacement.write_bytes(b"hostile")
    real_stat = os.stat

    def swapped_stat(path, *args, **kwargs):
        if os.fspath(path) == os.fspath(startup):
            return real_stat(replacement, *args, **kwargs)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr("angerona.modules.persistence_sweep.os.stat", swapped_stat)

    try:
        PersistenceSweepModule._startup_file_record(
            str(startup), budget_bytes=8192
        )
    except OSError as exc:
        assert "path changed" in str(exc)
    else:
        raise AssertionError("a post-hash path identity swap was accepted")
