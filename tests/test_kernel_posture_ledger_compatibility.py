"""Golden compatibility and resource bounds for the private ledger revision."""
import hashlib
import json
import os
import tracemalloc

import pytest

from angerona.modules import kernel_posture_ledger as ledger


def _instance(tmp_path, max_records=8):
    return ledger.KernelPostureLedger(
        tmp_path / "posture.jsonl", max_records=max_records, authority_key=b"k" * 32,
    )


@pytest.mark.parametrize("encoding", [
    "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be",
])
def test_encoding_rejected_by_original_string_reader_remains_rejected(tmp_path, encoding):
    instance = _instance(tmp_path)
    instance.path.write_bytes('{"a":1}\n'.encode(encoding))
    original = instance.path.read_bytes()
    # This is the actual original input contract, including native universal
    # newline handling; it must fail before any authenticated append is tried.
    with pytest.raises((ValueError, UnicodeError)):
        [json.loads(line) for line in instance.path.read_text(encoding="utf-8").splitlines()]
    with pytest.raises(RuntimeError):
        instance.read()
    with pytest.raises(RuntimeError):
        instance.append({"safe": True}, ts=1.0)
    assert instance.path.read_bytes() == original


def test_invalid_utf8_remains_rejected_without_rewrite(tmp_path):
    instance = _instance(tmp_path)
    payload = b'{"a":"\xff"}\n'
    instance.path.write_bytes(payload)
    with pytest.raises(RuntimeError):
        instance.read()
    with pytest.raises(RuntimeError):
        instance.append({"safe": True}, ts=1.0)
    assert instance.path.read_bytes() == payload


@pytest.mark.parametrize("separator", [
    "\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029",
], ids=["LF", "CR", "CRLF", "VT", "FF", "FS", "GS", "RS", "NEL", "LS", "PS"])
def test_all_legacy_string_line_separators_still_parse(tmp_path, separator):
    instance = _instance(tmp_path)
    instance.path.write_bytes(('{"a":1}' + separator + '{"b":2}' + separator).encode("utf-8"))
    expected = [json.loads(line) for line in instance.path.read_text(encoding="utf-8").splitlines()]
    assert expected == [{"a": 1}, {"b": 2}]
    assert instance.read() == expected


def test_many_short_records_refused_before_json_without_millions_of_line_objects(tmp_path, monkeypatch):
    instance = _instance(tmp_path, max_records=256)
    with instance.path.open("wb") as stream:
        stream.write(b"{}\n" * ((ledger.MAX_LEDGER_BYTES - 1) // 3))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("record-budget failure reached JSON parsing")

    monkeypatch.setattr(ledger.json, "loads", forbidden)
    tracemalloc.start()
    try:
        with pytest.raises(RuntimeError, match="record bound"):
            instance.read()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # The retained bytes + decoded text are bounded. A full split of ~5.6M
    # short lines consumes hundreds of MiB and violates this broad ceiling.
    assert peak < 96 * 1024 * 1024


def test_native_old_writer_bytes_match_after_every_append_and_retention(tmp_path):
    instance = _instance(tmp_path)
    golden = tmp_path / "old-writer.jsonl"
    observed_hashes = []
    for index in range(12):
        record = instance.append(
            {"index": index, "name": "驱动", "escaped": "\n\r\u2028", "driver_collected_at": float(index)},
            ts=float(index),
        )
        rows = instance.read()
        assert rows[-1] == record and instance.verify()[0]
        # Preserve the exact prior serialization code and native TextIO newline
        # translation. read_bytes compares actual physical bytes on this OS.
        golden.write_text(
            "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8",
        )
        expected = golden.read_bytes()
        assert instance.path.read_bytes() == expected
        if os.name == "nt":
            assert expected.count(b"\r\n") == len(rows)
        observed_hashes.append(hashlib.sha256(expected).hexdigest())
    assert len(set(observed_hashes)) == 12
    assert len(instance.read()) == 8 and instance.read()[0]["anchor"] is True


def test_total_physical_byte_limit_preserves_previous_file(tmp_path, monkeypatch):
    instance = _instance(tmp_path)
    first = instance.append({"safe": True}, ts=1.0)
    before = instance.path.read_bytes()
    # Choose a limit that admits the current actual physical file but excludes
    # the next append. The record remains independently within its own limit.
    monkeypatch.setattr(ledger, "MAX_LEDGER_BYTES", len(before))
    with pytest.raises(ValueError, match="ledger exceeds its byte bound"):
        instance.append({"safe": True}, ts=2.0)
    assert instance.path.read_bytes() == before
    assert instance.read() == [first] and instance.verify()[0]
    assert not list(tmp_path.glob("*.tmp.*"))
