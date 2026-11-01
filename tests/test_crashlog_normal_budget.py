from __future__ import annotations

import datetime
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from angerona.core import crashlog


@pytest.fixture
def budget(tmp_path, monkeypatch):
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 30, 12, 0, 0, tzinfo=tz)

    paths = {role: tmp_path / f"{role}-crash.log" for role in crashlog._NORMAL_ROLES}
    for path in paths.values():
        path.write_bytes(b"")
    monkeypatch.setattr(crashlog, "datetime", SimpleNamespace(datetime=Clock, timezone=datetime.timezone))
    monkeypatch.setattr(crashlog, "_NORMAL_PATHS", paths)
    monkeypatch.setattr(crashlog, "_NORMAL_ROWS",
                        {role: crashlog._NormalTarget(role) for role in crashlog._NORMAL_ROLES})
    monkeypatch.setattr(crashlog, "_NORMAL_SUPPRESSIONS",
                        {role: (0, 0, 0, "") for role in crashlog._NORMAL_ROLES})
    monkeypatch.setattr(crashlog, "_NORMAL_COUNT_GAP", False)
    monkeypatch.setattr(crashlog, "_NORMAL_LOCK", threading.Lock())
    monkeypatch.setattr(crashlog, "_NORMAL_STATS_LOCK", threading.Lock())
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(crashlog, "_NORMAL_MESSAGE_BYTES", 64 * 1024)
    monkeypatch.setattr(crashlog, "_NORMAL_PAUSED", False)
    monkeypatch.setattr(crashlog, "_NORMAL_CONFIGURED_AT", None)
    monkeypatch.setattr(crashlog, "_NORMAL_CACHE", crashlog._NORMAL_CACHE)
    crashlog._cache_normal_budget()
    return SimpleNamespace(paths=paths, root=tmp_path)


def _expected(kind="UNIT", text="payload"):
    return ("\n" + "=" * 72 + "\n[2026-10-30T12:00:00] " + kind + "\n" +
            "-" * 72 + "\n" + text + "\n").encode("utf-8", errors="backslashreplace")


def _rows():
    return {row["role"]: row for row in crashlog.normal_write_snapshot()["targets"]}


def test_defaults_complete_byte_accounting_and_memory_only_snapshot(budget, monkeypatch):
    before = crashlog.normal_write_snapshot()
    assert before["limit_bytes"] == 8 * 1024 * 1024 and before["message_bytes"] == 64 * 1024
    assert before["configured_at"] is None and not before["paused"]
    assert crashlog._write("UNIT", "payload") == {path: "" for path in budget.paths.values()}
    expected = _expected()
    for path in budget.paths.values():
        assert path.read_bytes() == expected
    snapshot = crashlog.normal_write_snapshot()
    assert not snapshot["native_fault_bytes_limited"] and not snapshot["external_writers_limited"]
    assert not snapshot["os_quota"] and snapshot["observations_cached"]
    for row in snapshot["targets"]:
        assert row["reserved_bytes"] == row["appended_bytes"] == len(expected)
        assert row["appended_blocks"] == 1 and row["suppressed_blocks"] == 0
        assert row["checked_size_bytes"] == 0 and row["checked_at"].endswith("+00:00")
    monkeypatch.setattr(crashlog, "open", lambda *_a, **_k: pytest.fail("getter attempted I/O"), raising=False)
    monkeypatch.setattr(crashlog, "fstat", lambda *_a: pytest.fail("getter queried size"))
    crashlog._NORMAL_LOCK.acquire()
    try:
        assert crashlog.normal_write_snapshot() == snapshot
    finally:
        crashlog._NORMAL_LOCK.release()
    # Returned rows cannot mutate the published cache.
    snapshot["targets"][0]["reserved_bytes"] = -1
    assert _rows()["logs"]["reserved_bytes"] == len(expected)


@pytest.mark.parametrize("extra", [0, -1], ids=["exact-limit", "one-byte-over"])
def test_complete_block_must_fit_file_and_process_limit(budget, monkeypatch, extra):
    expected = _expected()
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", len(expected) + extra)
    result = crashlog._write("UNIT", "payload")
    for role, path in budget.paths.items():
        assert path.read_bytes() == (expected if extra == 0 else b"")
        assert result[path] == ("" if extra == 0 else "normal-write:file-limit")
        assert _rows()[role]["reserved_bytes"] == (len(expected) if extra == 0 else 0)
    crashlog._write("UNIT", "payload")
    assert all(row["state"] == "held" and row["suppressed_blocks"] >= 1 for row in _rows().values())


def test_utf8_and_headers_count_toward_message_budget_without_partial_prefix(budget, monkeypatch):
    text = "é" * 40
    expected = _expected(text=text)
    monkeypatch.setattr(crashlog, "_NORMAL_MESSAGE_BYTES", len(expected) - 1)
    assert set(crashlog._write("UNIT", text).values()) == {"normal-write:message-limit"}
    assert all(path.read_bytes() == b"" for path in budget.paths.values())
    assert all(row["suppressed_known_bytes"] == len(expected) for row in _rows().values())
    monkeypatch.setattr(crashlog, "_NORMAL_MESSAGE_BYTES", len(expected))
    assert set(crashlog._write("UNIT", text).values()) == {""}
    assert all(path.read_bytes() == expected for path in budget.paths.values())


@pytest.mark.parametrize("huge_kind", [False, True], ids=["huge-body", "huge-kind"])
def test_giant_input_is_rejected_before_clock_encoding_or_file_io(budget, monkeypatch, huge_kind):
    def forbidden(*_a, **_k):
        pytest.fail("giant rejection attempted block construction or I/O")
    monkeypatch.setattr(crashlog, "datetime", SimpleNamespace(datetime=SimpleNamespace(now=forbidden)))
    monkeypatch.setattr(crashlog, "open", forbidden, raising=False)
    giant = "private-payload" * 100_000
    assert set(crashlog._write(giant if huge_kind else "UNIT", "" if huge_kind else giant).values()) == {
        "normal-write:message-limit"}
    assert all(row["suppressed_unknown_size_blocks"] == 1 for row in _rows().values())
    assert "private-payload" not in json.dumps(crashlog.normal_write_snapshot())


def test_invalid_message_never_calls_attacker_supplied_conversion_or_encoding(budget):
    class Hostile(str):
        def encode(self, *_a, **_k):
            pytest.fail("untrusted encoding called")
        def __str__(self):
            pytest.fail("untrusted conversion called")
    assert set(crashlog._write("UNIT", Hostile("private")).values()) == {"normal-write:message-invalid"}
    assert all(path.read_bytes() == b"" for path in budget.paths.values())


def test_existing_oversized_bytes_are_preserved_and_held_without_repeat_io(budget, monkeypatch):
    original = b"private-original-evidence\n" * 100
    for path in budget.paths.values():
        path.write_bytes(original)
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", len(original) - 1)
    assert set(crashlog._write("UNIT", "payload").values()) == {"normal-write:file-limit"}
    assert all(path.read_bytes() == original for path in budget.paths.values())
    monkeypatch.setattr(crashlog, "open", lambda *_a, **_k: pytest.fail("held writer reopened file"), raising=False)
    crashlog._write("UNIT", "payload")
    assert all(row["checked_size_bytes"] == len(original) and row["reserved_bytes"] == 0
               for row in _rows().values())
    assert "private-original-evidence" not in json.dumps(crashlog.normal_write_snapshot())


def test_file_replacement_does_not_refund_process_allowance(budget, monkeypatch):
    size = len(_expected())
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", size * 2)
    crashlog._write("UNIT", "payload")
    # These are unarmed test files. Simulate an outside replacement, never a
    # product cleanup action or a retained native fault stream.
    for path in budget.paths.values():
        path.unlink()
        path.write_bytes(b"")
    crashlog._write("UNIT", "payload")
    assert all(row["reserved_bytes"] == size * 2 and row["reason"] == "process-limit"
               for row in _rows().values())
    for path in budget.paths.values():
        path.write_bytes(b"")
    assert set(crashlog._write("UNIT", "payload").values()) == {"normal-write:process-limit"}
    assert all(path.read_bytes() == b"" for path in budget.paths.values())


def test_pause_and_resume_require_next_opened_file_validation_without_setter_io(budget, monkeypatch):
    crashlog._write("UNIT", "payload")
    original = {path: path.read_bytes() for path in budget.paths.values()}
    old_checks = tuple(row["checked_size_bytes"] for row in _rows().values())
    real_open = open
    monkeypatch.setattr(crashlog, "open", lambda *_a, **_k: pytest.fail("setter or paused writer performed I/O"),
                        raising=False)
    result = crashlog.configure_normal_log_budget(limit_mib=1, message_kib=4, paused=True)
    assert result["accepted"] and result["snapshot"]["configured_at"] is not None
    assert set(crashlog._write("UNIT", "payload").values()) == {"normal-write:policy-paused"}
    resumed = crashlog.configure_normal_log_budget(limit_mib=2, message_kib=8, paused=False)
    assert resumed["accepted"]
    assert all(row["reason"] == "resume-check-required" for row in _rows().values())
    assert tuple(row["checked_size_bytes"] for row in _rows().values()) == old_checks
    assert all(row["suppressed_blocks"] == 1 for row in _rows().values())
    monkeypatch.setattr(crashlog, "open", real_open)
    crashlog._write("UNIT", "payload")
    assert all(row["checked_size_bytes"] == len(_expected()) and row["state"] == "ready"
               for row in _rows().values())
    assert all(path.read_bytes() == data + _expected() for path, data in original.items())


def test_capacity_increase_checks_existing_file_again_and_preserves_suppression(budget):
    original = b"E" * (1024 * 1024)
    for path in budget.paths.values():
        path.write_bytes(original)
    crashlog.configure_normal_log_budget(limit_mib=1, message_kib=4, paused=False)
    assert set(crashlog._write("UNIT", "payload").values()) == {"normal-write:file-limit"}
    assert all(path.read_bytes() == original for path in budget.paths.values())
    result = crashlog.configure_normal_log_budget(limit_mib=2, message_kib=4, paused=False)
    assert all(row["reason"] == "resume-check-required" for row in result["snapshot"]["targets"])
    assert set(crashlog._write("UNIT", "payload").values()) == {""}
    for row in _rows().values():
        assert row["checked_size_bytes"] == len(original)
        assert row["reserved_bytes"] == len(_expected()) and row["suppressed_blocks"] == 1
    assert all(path.read_bytes() == original + _expected() for path in budget.paths.values())


@pytest.mark.parametrize("mode,size", [(0, 0), (0o100600, -1), (0o100600, True)])
def test_unusable_opened_file_metadata_holds_without_writing_or_reconfiguration_bypass(
    budget, monkeypatch, mode, size,
):
    original = b"original evidence"
    for path in budget.paths.values():
        path.write_bytes(original)
    monkeypatch.setattr(crashlog, "fstat", lambda _fd: SimpleNamespace(st_mode=mode, st_size=size))
    crashlog._write("UNIT", "payload")
    assert all(path.read_bytes() == original for path in budget.paths.values())
    assert all(row["reason"] == "io-uncertain" and row["reserved_bytes"] == 0 for row in _rows().values())
    monkeypatch.setattr(crashlog, "open", lambda *_a, **_k: pytest.fail("metadata failure bypassed hold"), raising=False)
    crashlog.configure_normal_log_budget(limit_mib=64, message_kib=256, paused=False)
    assert set(crashlog._write("UNIT", "payload").values()) == {"normal-write:io-uncertain"}


@pytest.mark.parametrize("field,value", [
    ("limit_mib", True), ("limit_mib", 0), ("limit_mib", 65), ("limit_mib", "8"),
    ("message_kib", False), ("message_kib", 3), ("message_kib", 257), ("message_kib", 4.0),
    ("paused", 0), ("paused", "false"),
])
def test_invalid_controls_leave_policy_counters_and_files_unchanged(budget, field, value):
    before = crashlog.normal_write_snapshot()
    arguments = dict(limit_mib=8, message_kib=64, paused=False)
    arguments[field] = value
    with pytest.raises(ValueError):
        crashlog.configure_normal_log_budget(**arguments)
    assert crashlog.normal_write_snapshot() == before
    assert all(path.read_bytes() == b"" for path in budget.paths.values())


def test_writer_and_configuration_do_not_wait_on_busy_writer_or_emit_recursive_warning(budget, monkeypatch, capsys):
    monkeypatch.setattr(crashlog, "open", lambda *_a, **_k: pytest.fail("contended writer performed I/O"), raising=False)
    crashlog._NORMAL_LOCK.acquire()
    try:
        assert set(crashlog._write("UNIT", "payload").values()) == {"normal-write:lock-contention"}
        result = crashlog.configure_normal_log_budget(limit_mib=1, message_kib=4, paused=True)
        assert not result["accepted"] and result["reason"] == "writer-busy"
        assert all(row["suppressed_blocks"] == 1 for row in result["snapshot"]["targets"])
        assert not result["snapshot"]["paused"]
    finally:
        crashlog._NORMAL_LOCK.release()
    assert capsys.readouterr().err == ""


def test_contended_telemetry_reports_count_gap_without_waiting_or_recursive_logging(budget):
    crashlog._NORMAL_LOCK.acquire()
    crashlog._NORMAL_STATS_LOCK.acquire()
    try:
        crashlog._write("UNIT", "payload")
        snapshot = crashlog.normal_write_snapshot()
        assert snapshot["suppression_counts_lower_bound"]
        assert all(row["suppressed_blocks"] == 0 for row in snapshot["targets"])
    finally:
        crashlog._NORMAL_STATS_LOCK.release()
        crashlog._NORMAL_LOCK.release()


@pytest.mark.parametrize("failure", ["short", "write", "flush", "close"])
def test_uncertain_io_never_refunds_reservation_or_resumes_on_configuration(budget, monkeypatch, failure):
    real_open = open
    class Faulty:
        def __init__(self, path, *args, **kwargs):
            self.stream = real_open(path, *args, **kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            self.stream.close()
            if failure == "close":
                raise OSError("private-close-secret")
        def fileno(self):
            return self.stream.fileno()
        def write(self, block):
            if failure in ("short", "write"):
                self.stream.write(block[:7])
                if failure == "write":
                    raise OSError("private-write-secret")
                return 7
            return self.stream.write(block)
        def flush(self):
            if failure == "flush":
                raise OSError("private-flush-secret")
            self.stream.flush()
    monkeypatch.setattr(crashlog, "open", Faulty, raising=False)
    crashlog._write("UNIT", "payload")
    assert all(path.read_bytes() == (_expected()[:7] if failure in ("short", "write") else _expected())
               for path in budget.paths.values())
    for row in _rows().values():
        assert row["reserved_bytes"] == row["uncertain_bytes"] == len(_expected())
        assert row["appended_bytes"] == 0 and row["reason"] == "io-uncertain"
    monkeypatch.setattr(crashlog, "open", lambda *_a, **_k: pytest.fail("uncertain writer reopened evidence"))
    crashlog.configure_normal_log_budget(limit_mib=64, message_kib=256, paused=False)
    assert set(crashlog._write("UNIT", "payload").values()) == {"normal-write:io-uncertain"}
    assert all(row["reserved_bytes"] == len(_expected()) for row in _rows().values())
    assert "private-" not in json.dumps(crashlog.normal_write_snapshot())


def test_native_fault_streams_are_never_closed_written_rotated_or_rearmed(budget, monkeypatch):
    class NativeStream:
        def close(self):
            pytest.fail("normal budget closed native stream")
        def write(self, *_a):
            pytest.fail("normal budget wrote through native stream")
    streams = [NativeStream(), NativeStream()]
    monkeypatch.setattr(crashlog, "_FH_FILES", streams)
    monkeypatch.setattr(crashlog.faulthandler, "enable", lambda **_k: pytest.fail("budget rearmed native capture"))
    crashlog.configure_normal_log_budget(limit_mib=1, message_kib=4, paused=True)
    crashlog._write("UNIT", "payload")
    crashlog.configure_normal_log_budget(limit_mib=1, message_kib=4, paused=False)
    crashlog._write("UNIT", "payload")
    assert crashlog._FH_FILES is streams and len(streams) == 2


def test_concurrent_writer_suppression_preserves_serialized_allowance_and_cached_reads(budget, monkeypatch):
    real_open = open
    entered, release = threading.Event(), threading.Event()
    class Waiting:
        def __init__(self, path, *args, **kwargs):
            self.path, self.stream = Path(path), real_open(path, *args, **kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            self.stream.close()
        def fileno(self):
            return self.stream.fileno()
        def write(self, block):
            if self.path == budget.paths["logs"]:
                entered.set()
                assert release.wait(3), "test writer release timed out"
            return self.stream.write(block)
        def flush(self):
            self.stream.flush()
    monkeypatch.setattr(crashlog, "open", Waiting, raising=False)
    monkeypatch.setattr(crashlog, "_NORMAL_LIMIT_BYTES", len(_expected()))
    result = []
    writer = threading.Thread(target=lambda: result.append(crashlog._write("UNIT", "payload")))
    writer.start()
    try:
        assert entered.wait(3), "test writer did not reach owned append"
        assert set(crashlog._write("UNIT", "second").values()) == {"normal-write:lock-contention"}
        cached = crashlog.normal_write_snapshot()
        assert all(row["suppressed_blocks"] == 1 for row in cached["targets"])
        assert not crashlog.configure_normal_log_budget(limit_mib=1, message_kib=4, paused=False)["accepted"]
    finally:
        release.set()
        writer.join(3)
    assert not writer.is_alive() and len(result) == 1
    assert all(row["reserved_bytes"] == len(_expected()) for row in _rows().values())
    assert all(path.read_bytes() == _expected() for path in budget.paths.values())
