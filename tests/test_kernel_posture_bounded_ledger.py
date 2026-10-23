"""Optional ledger proposal: private local files, no watchers or host actions."""
import hashlib
import json
import os

import pytest

from angerona.core import agent_integrity
from angerona.modules import kernel_posture_ledger as ledger


def _ledger(tmp_path, max_records=8):
    return ledger.KernelPostureLedger(
        tmp_path / "posture.jsonl", max_records=max_records, authority_key=b"k" * 32,
    )


def test_oversize_file_rejected_before_payload_read(tmp_path, monkeypatch):
    instance = _ledger(tmp_path)
    with instance.path.open("wb") as stream:
        stream.truncate(ledger.MAX_LEDGER_BYTES + 1)
    opened = []
    original_open = agent_integrity._open_sealed

    class NoPayloadRead:
        def __enter__(self):
            self.stream = original_open(instance.path)
            return self

        def __exit__(self, *_args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, *_args):
            raise AssertionError("oversize ledger payload was read")

    def intercept(path):
        opened.append(path)
        return NoPayloadRead()

    monkeypatch.setattr(agent_integrity, "_open_sealed", intercept)
    with pytest.raises(RuntimeError, match="bounded"):
        instance.read()
    assert opened == [instance.path]


@pytest.mark.parametrize("payload,reason", [
    (b"{}\n" * 9, "record bound"),
    (b'{"x":"' + b"a" * (64 * 1024) + b'"}\n', "byte bound"),
], ids=["too-many-rows", "oversized-record"])
def test_row_and_line_bounds_precede_json_parser(tmp_path, monkeypatch, payload, reason):
    instance = _ledger(tmp_path)
    instance.path.write_bytes(payload)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("out-of-budget ledger reached the JSON parser")

    monkeypatch.setattr(ledger.json, "loads", forbidden)
    with pytest.raises(RuntimeError, match=reason):
        instance.read()


def test_hardlink_ledger_is_rejected_without_rewrite(tmp_path):
    instance = _ledger(tmp_path)
    instance.append({"driver_collected_at": 1.0}, ts=1.0)
    alias = tmp_path / "alias.jsonl"
    os.link(instance.path, alias)
    original = alias.read_bytes()
    assert not instance.verify()[0]
    with pytest.raises(RuntimeError, match="bounded and single-link"):
        instance.append({"driver_collected_at": 2.0})
    assert alias.read_bytes() == original


def test_named_identity_replacement_is_rejected(tmp_path, monkeypatch):
    instance = _ledger(tmp_path)
    instance.append({"driver_collected_at": 1.0}, ts=1.0)
    original_stat = type(instance.path).stat

    def replaced(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == instance.path and kwargs.get("follow_symlinks") is False:
            class Replaced:
                st_dev = result.st_dev
                st_ino = result.st_ino + 1
                st_size = result.st_size
                st_mtime_ns = result.st_mtime_ns
            return Replaced()
        return result

    monkeypatch.setattr(type(instance.path), "stat", replaced)
    assert not instance.verify()[0]


def test_append_outside_line_budget_preserves_previous_signed_chain(tmp_path):
    instance = _ledger(tmp_path)
    instance.append({"safe": True}, ts=1.0)
    before = instance.path.read_bytes()
    with pytest.raises(ValueError, match="byte bound"):
        instance.append({"oversized": "x" * ledger.MAX_LEDGER_RECORD_BYTES}, ts=2.0)
    assert instance.path.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp.*"))
    assert instance.verify()[0]


def test_same_signed_record_bytes_and_digest_survive_read_change(tmp_path):
    instance = _ledger(tmp_path)
    record = instance.append({"name": "驱动", "driver_collected_at": 1.0}, ts=2.0)
    legacy = tmp_path / "legacy-writer.jsonl"
    legacy.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8",
    )
    expected = legacy.read_bytes()
    assert instance.path.read_bytes() == expected
    if os.name == "nt":
        assert expected.endswith(b"\r\n")
    assert instance.read() == [record]
    assert instance.verify()[0]
    changed = json.loads(expected)
    changed["snapshot"]["driver_collected_at"] = 7.0
    instance.path.write_bytes((json.dumps(changed) + "\n").encode())
    assert not instance.verify()[0]


def test_timestamp_only_refresh_is_not_drift_but_remains_signed_evidence(tmp_path):
    snapshots = [
        dict(driver_collected_at=1.0, driver_set_sha256="a", driver_collection_status="complete"),
        dict(driver_collected_at=2.0, driver_set_sha256="a", driver_collection_status="complete"),
        dict(driver_collected_at=3.0, driver_set_sha256="b", driver_collection_status="partial"),
    ]

    class Provider:
        def snapshot(self):
            return snapshots.pop(0)

    module = ledger.KernelBoundaryPostureLedger(
        provider=Provider(), ledger_path=tmp_path / "drift.jsonl", authority_key=b"k" * 32,
    )
    first, _, initial = module.observe_once()
    second, _, timestamp_only = module.observe_once()
    third, _, actual_drift = module.observe_once()
    assert initial == timestamp_only == []
    assert actual_drift == ["driver_collection_status", "driver_set_sha256"]
    rows = module._ledger.read()
    assert [row["snapshot"]["driver_collected_at"] for row in rows] == [1.0, 2.0, 3.0]
    assert ledger._digest(first) != ledger._digest(second) != ledger._digest(third)
    assert len({row["snapshot_sha256"] for row in rows}) == 3
    assert module._ledger.verify()[0]
    # Full authenticated evidence deliberately changes with fresh receipt time;
    # only the user-facing posture drift comparison ignores that metadata.
    assert hashlib.sha256(ledger._canonical(first)).hexdigest() == rows[0]["snapshot_sha256"]
