from __future__ import annotations

import json
import os
import struct
import ctypes
from ctypes import wintypes

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules import file_integrity as fim


def _module(tmp_path, monkeypatch, watch_root):
    monkeypatch.setattr(fim, "watch_roots", lambda: [str(watch_root)])
    module = fim.FileIntegrityModule()
    module._baseline_path_override = tmp_path / "fim-baseline.json"
    module._baseline_key_override = b"K" * 32
    return module


def test_baseline_requires_explicit_complete_review_and_is_authenticated(
    tmp_path, monkeypatch
) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "policy.conf"
    target.write_text("allow=false\n", encoding="utf-8")
    module = _module(tmp_path, monkeypatch, watched)
    module._baseline = module._scan()
    module._driver_baseline = {"reviewed.sys"}

    with pytest.raises(PermissionError):
        module.approve_current_baseline()
    destination = module.approve_current_baseline(approved=True)

    loaded_module = _module(tmp_path, monkeypatch, watched)
    loaded = loaded_module._load_approved_baseline()
    assert loaded is not None
    files, drivers = loaded
    assert files == module._baseline
    assert drivers == {"reviewed.sys"}
    assert loaded_module._baseline_status == "approved"

    document = json.loads(destination.read_text("utf-8"))
    document["files"][str(target)] = "0" * 64
    destination.write_text(json.dumps(document), encoding="utf-8")
    tampered_module = _module(tmp_path, monkeypatch, watched)
    assert tampered_module._load_approved_baseline() is None
    assert tampered_module._baseline_status == "invalid"


def test_missing_approved_file_is_detected_on_first_complete_scan(
    tmp_path, monkeypatch
) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "startup-target.bin"
    target.write_bytes(b"trusted")
    module = _module(tmp_path, monkeypatch, watched)
    module._baseline = module._scan()
    module._driver_baseline = set()
    module.approve_current_baseline(approved=True)

    restarted = _module(tmp_path, monkeypatch, watched)
    loaded = restarted._load_approved_baseline()
    assert loaded is not None
    restarted._baseline, restarted._driver_baseline = loaded
    bus = EventBus()
    restarted.bind(bus)
    target.unlink()

    current = restarted._scan()
    assert restarted._last_scan_receipt["complete"] is True
    restarted._evaluate_snapshot(current)

    events = bus.recent(20)
    assert any(
        event.details.get("path") == str(target) and "deleted" in event.message
        for event in events
    )


def test_metadata_preserving_rewrite_invalidates_windows_change_token_cache(
    tmp_path, monkeypatch
) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "same-size.bin"
    target.write_bytes(b"AAAA")
    module = _module(tmp_path, monkeypatch, watched)
    monkeypatch.setattr(module, "_handle_usn", lambda _descriptor: None)
    first = module._scan()
    assert first, module._last_scan_receipt
    module._baseline = first
    before = target.stat()

    target.write_bytes(b"BBBB")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    second = module._scan()

    assert str(target) in first, (tuple(first), str(target))
    assert str(target) in second, module._last_scan_receipt
    assert first[str(target)] != second[str(target)]
    assert module._last_scan_receipt["files_hashed"] == 1
    assert module._last_scan_receipt["hashes_reused"] == 0


def test_windows_usn_parser_accepts_v2_v3_and_rejects_untrusted_shapes() -> None:
    def _record(major: int, length: int, offset: int, usn: int) -> bytes:
        raw = bytearray(length)
        struct.pack_into("<IHH", raw, 0, length, major, 0)
        struct.pack_into("<q", raw, offset, usn)
        return bytes(raw)

    assert fim._parse_windows_file_usn(_record(2, 64, 24, 101)) == 101
    assert fim._parse_windows_file_usn(_record(3, 80, 40, 202)) == 202
    assert fim._parse_windows_file_usn(b"") is None
    assert fim._parse_windows_file_usn(_record(4, 80, 40, 303)) is None
    assert fim._parse_windows_file_usn(_record(2, 56, 24, 404)) is None

    truncated = bytearray(_record(2, 64, 24, 505))
    struct.pack_into("<I", truncated, 0, 72)
    assert fim._parse_windows_file_usn(bytes(truncated)) is None
    assert fim._parse_windows_file_usn(_record(2, 68, 24, 606)) is None
    assert fim._parse_windows_file_usn(_record(2, 64, 24, 0)) is None
    assert fim._parse_windows_file_usn(_record(2, 64, 24, -1)) is None


def test_windows_usn_binding_failures_disable_cache_acceleration(
    tmp_path, monkeypatch
) -> None:
    class _ReadFileUsnData(ctypes.Structure):
        _fields_ = [
            ("MinMajorVersion", wintypes.WORD),
            ("MaxMajorVersion", wintypes.WORD),
        ]

    class _Msvcrt:
        @staticmethod
        def get_osfhandle(descriptor: int) -> int:
            return descriptor

    target = tmp_path / "binding.bin"
    target.write_bytes(b"AAAA")
    descriptor = os.open(
        target, os.O_RDONLY | getattr(os, "O_BINARY", 0)
    )
    try:
        monkeypatch.setattr(
            fim,
            "_windows_usn_api",
            lambda: (
                ctypes,
                _Msvcrt,
                wintypes,
                _ReadFileUsnData,
                lambda *_args: 0,
            ),
        )
        assert fim.FileIntegrityModule._handle_usn(descriptor) is None

        malformed = bytearray(80)
        struct.pack_into("<IHH", malformed, 0, 80, 4, 0)

        def _malformed_device_io(
            _handle,
            _control,
            _input,
            _input_size,
            output,
            _output_size,
            returned,
            _overlapped,
        ) -> int:
            ctypes.memmove(output, bytes(malformed), len(malformed))
            ctypes.cast(
                returned, ctypes.POINTER(wintypes.DWORD)
            ).contents.value = len(malformed)
            return 1

        monkeypatch.setattr(
            fim,
            "_windows_usn_api",
            lambda: (
                ctypes,
                _Msvcrt,
                wintypes,
                _ReadFileUsnData,
                _malformed_device_io,
            ),
        )
        assert fim.FileIntegrityModule._handle_usn(descriptor) is None
    finally:
        os.close(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows per-file USN contract")
def test_windows_composite_token_changes_for_rapid_metadata_preserving_rewrites(
    tmp_path,
) -> None:
    target = tmp_path / "usn-change.bin"
    target.write_bytes(b"AAAA")

    def _token() -> int | None:
        descriptor = os.open(
            target, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
        try:
            usn = fim.FileIntegrityModule._handle_usn(descriptor)
            if usn is None:
                return None
            change_time = fim.FileIntegrityModule._handle_change_token(descriptor)
            return (usn << 64) | (change_time & ((1 << 64) - 1))
        finally:
            os.close(descriptor)

    previous = _token()
    if previous is None:
        pytest.skip("per-file USN unavailable; production uses full hashing")
    for index in range(32):
        before = target.stat()
        target.write_bytes(b"BBBB" if index % 2 == 0 else b"AAAA")
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        current = _token()
        assert current is not None
        assert current != previous
        previous = current


def test_incomplete_root_never_reports_green_or_allows_approval(
    tmp_path, monkeypatch
) -> None:
    missing = tmp_path / "missing"
    module = _module(tmp_path, monkeypatch, missing)
    module._baseline_status = "approved"
    module._driver_collection_ok = True
    module._baseline = module._scan()

    module._set_coverage_health()

    assert module._last_scan_receipt["complete"] is False
    assert module.health <= 35
    assert "unavailable" in module.health_note
    with pytest.raises(RuntimeError):
        module.approve_current_baseline(approved=True)
