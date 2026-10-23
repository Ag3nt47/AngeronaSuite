"""Performance changes retain the scanner's cursor and authority decisions."""
from __future__ import annotations

from pathlib import Path

import pytest

from angerona.modules import yara_scanner
from angerona.modules.yara_scanner import YaraScannerModule


@pytest.mark.parametrize("limit", [1, 3, 5, 10])
@pytest.mark.parametrize(
    ("cursor", "rotation", "wrapped"),
    [
        ("", ("a.bin", "B.bin", "ss.bin", "ß.bin", "Z.bin"), False),
        ("B.bin", ("ss.bin", "ß.bin", "Z.bin", "a.bin", "B.bin"), False),
        ("SS.bin", ("ss.bin", "ß.bin", "Z.bin", "a.bin", "B.bin"), False),
        ("ss.bin", ("ß.bin", "Z.bin", "a.bin", "B.bin", "ss.bin"), False),
        ("ß.bin", ("Z.bin", "a.bin", "B.bin", "ss.bin", "ß.bin"), False),
        ("missing.bin", ("ss.bin", "ß.bin", "Z.bin", "a.bin", "B.bin"), False),
        ("zz.bin", ("a.bin", "B.bin", "ss.bin", "ß.bin", "Z.bin"), True),
    ],
)
def test_cursor_rotation_retains_ties_missing_cursors_and_single_visit(
    tmp_path, monkeypatch, limit, cursor, rotation, wrapped,
):
    for name in ("Z.bin", "ß.bin", "B.bin", "ss.bin", "a.bin"):
        (tmp_path / name).write_bytes(b"inert")
    monkeypatch.setattr(yara_scanner, "MAX_FILES_PER_ROOT", limit)

    batch = YaraScannerModule._fair_batch(tmp_path, cursor)

    assert tuple(path.name for path in batch.paths) == rotation[:limit]
    assert len(set(batch.paths)) == len(batch.paths)
    assert batch.discovered == 5
    assert batch.next_cursor == rotation[:limit][-1]
    assert batch.wrapped is wrapped
    assert batch.incomplete is (limit < 5)
    assert not batch.errors and not batch.discovery_truncated


@pytest.mark.parametrize("cursor", ["", "prior.bin"])
def test_empty_inventory_retains_cursor_without_selecting_paths(tmp_path, cursor):
    batch = YaraScannerModule._fair_batch(tmp_path, cursor)
    assert batch.paths == () and batch.next_cursor == cursor
    assert batch.wrapped is bool(cursor)
    assert not batch.incomplete


@pytest.mark.parametrize(
    ("header", "tokens", "expected"),
    [
        (b"MZ\x00PE\x00\x00", b"SeKuRlSa:: LOGONPASSWORDS GeNtIlKiWi", True),
        (b"MZ\x00PE\x00\x00", b"SeKuRlSa:: LOGONPASSWORDS", False),
        (b"MZ\x00PE\x00\x00", b"LOGONPASSWORDS GeNtIlKiWi", False),
        (b"MZ\x00PE\x00\x00", b"SeKuRlSa:: GeNtIlKiWi", False),
        (b"MZ\x00PE\x00\x00", b"unrelated", False),
        (b"notes PE\x00\x00", b"sekurlsa:: logonpasswords gentilkiwi", False),
        (b"MZ" + b"\x00" * 4094 + b"PE\x00\x00",
         b"sekurlsa:: logonpasswords gentilkiwi", False),
    ],
)
def test_binary_response_classification_retains_all_signature_requirements(header, tokens, expected):
    payload = header + b"\x00" * 8192 + tokens
    classification = YaraScannerModule._response_classification(
        Path("inert.bin"), payload, observed_content_sha256="0" * 64,
        observed_file_identity={"device": 1, "inode": 2, "birthtime_ns": 0},
    )
    assert classification == ("credential-dumper-binary-signatures" if expected else "")


class _OpenedReadProbe:
    """Keep real descriptor/stat behavior while observing only its content read."""

    def __init__(self, handle, read):
        self._handle = handle
        self._read = read

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, *args):
        return self._handle.__exit__(*args)

    def fileno(self):
        return self._handle.fileno()

    def read(self, size=-1):
        return self._read(self._handle, size)


def test_small_file_keeps_payload_positive_receipt_and_cache_without_cap_sized_read(
    tmp_path, monkeypatch,
):
    import hashlib
    from types import SimpleNamespace

    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.modules.file_integrity import FileIntegrityModule

    # This case asserts cache reuse, so Windows must have stable USN proof.
    monkeypatch.setattr(FileIntegrityModule, "_handle_usn", staticmethod(lambda _fd: 101))

    path = tmp_path / "small-positive.bin"
    payload = b"ANGERONA INERT READ-SIZE PROBE"
    path.write_bytes(payload)
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    module = YaraScannerModule()
    module.bind(bus)
    read_sizes, scanned = [], []
    real_fdopen = yara_scanner.os.fdopen

    def read(handle, size):
        read_sizes.append(size)
        assert 0 < size <= len(payload) + 1, "small file requested the full scan budget"
        return handle.read(size)

    monkeypatch.setattr(
        yara_scanner.os, "fdopen",
        lambda *args, **kwargs: _OpenedReadProbe(real_fdopen(*args, **kwargs), read),
    )

    class Scanner:
        def scan(self, content):
            scanned.append(content)
            return SimpleNamespace(matching_rules=[SimpleNamespace(identifier="Inert_Read_Probe")])

    scanner = Scanner()
    assert module._scan_file(scanner, path) == "scanned", module.last_error
    assert scanned == [payload] and len(read_sizes) == 1
    events = bus.recent(10)
    assert len(events) == 1
    event = events[0]
    assert bus.verify(event) and module.verify_detection_event(event)
    assert event.details["observed_content_sha256"] == hashlib.sha256(payload).hexdigest()
    assert event.details["rule"] == "Inert_Read_Probe"
    assert event.details["scan_complete"] is True
    assert event.details["response_authorized"] is False
    assert module._scan_cache
    assert module._scan_file(scanner, path) == "scanned", module.last_error
    assert scanned == [payload] and len(read_sizes) == 1
    assert len(bus.recent(10)) == 1


@pytest.mark.parametrize("mutation", ["append", "truncate"])
def test_read_time_size_change_is_refused_before_scan_receipt_or_cache(
    tmp_path, monkeypatch, mutation,
):
    from types import SimpleNamespace

    from angerona.core.eventbus import BusAuthority, EventBus

    path = tmp_path / "changing.bin"
    payload = b"ANGERONA INERT READ-SIZE PROBE"
    path.write_bytes(payload)
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    module = YaraScannerModule()
    module.bind(bus)
    observed, scanned = [], []
    real_fdopen = yara_scanner.os.fdopen

    def read(handle, size):
        with path.open("r+b") as writer:
            if mutation == "append":
                writer.seek(0, 2)
                writer.write(b"!")
            else:
                writer.truncate(len(payload) - 1)
        observed.append(path.stat().st_size)
        return handle.read(size)

    monkeypatch.setattr(
        yara_scanner.os, "fdopen",
        lambda *args, **kwargs: _OpenedReadProbe(real_fdopen(*args, **kwargs), read),
    )

    class Scanner:
        def scan(self, content):
            scanned.append(content)
            return SimpleNamespace(matching_rules=[SimpleNamespace(identifier="Inert_Read_Probe")])

    assert module._scan_file(Scanner(), path) == "failed"
    expected_size = len(payload) + (1 if mutation == "append" else -1)
    assert observed == [expected_size] and path.stat().st_size == expected_size
    assert not scanned
    assert not module._scan_cache and not module._detection_receipts
    assert not bus.recent(10)
    assert "size" in module.last_error
