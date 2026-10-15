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
