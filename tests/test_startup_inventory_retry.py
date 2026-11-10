"""A transient fingerprint deadline never bypasses source/close checks."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


SPEC = importlib.util.spec_from_file_location(
    "startup_inventory_under_test", Path(__file__).resolve().parents[1] / "tools/startup_source_recovery.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


@pytest.fixture
def source(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    directory = root / "src/angerona"
    directory.mkdir(parents=True)
    (directory / "a.py").write_bytes(b"A = 1\n")
    (directory / "b.py").write_bytes(b"B = 2\n")
    (directory / "nested").mkdir()
    (directory / "nested/c.py").write_bytes(b"C = 3\n")
    monkeypatch.setattr(recovery, "_FILE_CLOSE_HELD", False)
    return root


def clock(monkeypatch):
    value = [0.0]
    monkeypatch.setattr(recovery, "time", SimpleNamespace(monotonic=lambda: value[0]))
    return value


def test_success_still_reads_two_complete_inventories(source):
    observations = []
    result = recovery.fingerprint(source, observations)
    assert result["inventory_attempts"] == 1
    assert result["file_count"] == 3
    assert [(row["attempt"], row["pass_number"], row["files"], row["status"])
            for row in observations] == [(1, 1, 3, "complete"), (1, 2, 3, "complete")]
    assert result["inventory_passes"] == observations
    assert all(row["close_custody"] == "closed" for row in observations)


@pytest.mark.parametrize("expired_pass", [1, 2])
def test_one_time_expiry_discards_attempt_and_restarts_both_passes(source, monkeypatch, expired_pass):
    now = clock(monkeypatch)
    original = recovery.read
    reads = []
    events = []
    close = recovery.FileLease.close

    def acknowledge(owner):
        was_open = owner.fd >= 0
        close(owner)
        if was_open:
            events.append("closed")

    def slow_once(*args, **kwargs):
        data = original(*args, **kwargs)
        reads.append(args[0])
        if len(reads) == (expired_pass - 1) * 3 + 1:
            assert events[-1] == "closed"
            now[0] += 31
        return data

    monkeypatch.setattr(recovery.FileLease, "close", acknowledge)
    monkeypatch.setattr(recovery, "read", slow_once)
    observations = []
    result = recovery.fingerprint(source, observations)
    assert result["inventory_attempts"] == 2
    assert len(reads) == (expired_pass - 1) * 3 + 1 + 6
    assert len(events) == len(reads)
    assert observations[expired_pass - 1]["reason"] == "time"
    assert observations[expired_pass - 1]["elapsed_seconds"] == 31
    assert observations[-2]["files"] == observations[-1]["files"] == 3
    assert [(row["attempt"], row["pass_number"]) for row in observations[-2:]] == [(2, 1), (2, 2)]
    assert all(row["close_custody"] == "closed" for row in observations)
    assert result["inventory_passes"] == observations


def test_second_deadline_expiry_is_terminal(source, monkeypatch):
    now = clock(monkeypatch)
    original = recovery.read

    def slow_every_attempt(*args, **kwargs):
        data = original(*args, **kwargs)
        now[0] += 31
        return data

    monkeypatch.setattr(recovery, "read", slow_every_attempt)
    observations = []
    with pytest.raises(recovery.InventoryLimit) as error:
        recovery.fingerprint(source, observations)
    assert error.value.limit == "time"
    assert len(observations) == 2
    assert [row["attempt"] for row in observations] == [1, 2]
    assert all(row["reason"] == "time" and row["close_custody"] == "closed" for row in observations)


@pytest.mark.parametrize(("name", "limit"), [("MAX_ENTRIES", "entries"), ("MAX_FILES", "files"), ("MAX_BYTES", "bytes")])
def test_capacity_limits_never_retry(source, monkeypatch, name, limit):
    monkeypatch.setattr(recovery, name, 0)
    observations = []
    with pytest.raises(recovery.InventoryLimit) as error:
        recovery.fingerprint(source, observations)
    assert error.value.limit == limit
    assert len(observations) == 1
    assert observations[0]["attempt"] == 1
    assert observations[0]["reason"] == limit
    assert all(type(observations[0][key]) is int for key in ("visited", "directories", "read_calls", "files", "bytes"))


def test_source_change_between_complete_passes_never_retries(source, monkeypatch):
    original = recovery.inventory
    calls = []

    def changed(root, **kwargs):
        result = original(root, **kwargs)
        calls.append(True)
        if len(calls) == 1:
            (source / "src/angerona/a.py").write_bytes(b"A = 999\n")
        return result

    monkeypatch.setattr(recovery, "inventory", changed)
    observations = []
    with pytest.raises(recovery.Held, match="editor changed"):
        recovery.fingerprint(source, observations)
    assert len(calls) == len(observations) == 2
    assert all(row["attempt"] == 1 for row in observations)


def test_identity_failure_after_time_expiry_is_not_a_third_attempt(source, monkeypatch):
    now = clock(monkeypatch)
    original = recovery.read
    calls = []

    def changed(*args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise recovery.Held("Recovery file changed while opening")
        result = original(*args, **kwargs)
        now[0] += 31
        return result

    monkeypatch.setattr(recovery, "read", changed)
    observations = []
    with pytest.raises(recovery.Held, match="changed while opening"):
        recovery.fingerprint(source, observations)
    assert len(calls) == len(observations) == 2
    assert [row["reason"] for row in observations] == ["time", "input-held"]


def test_hardlinked_source_is_held_without_retry(source):
    path = source / "src/angerona/a.py"
    os.link(path, source / "other-name.py")
    observations = []
    with pytest.raises(recovery.Held, match="single-link"):
        recovery.fingerprint(source, observations)
    assert len(observations) == 1
    assert observations[0]["reason"] == "input-held"


def test_reparse_source_directory_is_held_without_retry(source, monkeypatch):
    directory = source / "src/angerona/nested"
    original = Path.lstat

    def redirected(path):
        value = original(path)
        if path != directory:
            return value
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
        fields["st_file_attributes"] = 0x400
        return SimpleNamespace(**fields)

    monkeypatch.setattr(Path, "lstat", redirected)
    observations = []
    with pytest.raises(recovery.Held, match="redirected"):
        recovery.fingerprint(source, observations)
    assert len(observations) == 1 and observations[0]["reason"] == "input-held"


def test_only_existing_ineligible_directories_are_pruned(source):
    directory = source / "src/angerona"
    for name in (".git", ".tmp", "__pycache__", "external_modules", "external-modules"):
        (directory / name).mkdir()
        (directory / name / "ignored.py").write_bytes(b"ignored")
    observations = []
    assert len(recovery.inventory(source, observations=observations)) == 3
    assert observations[0]["directories"] == 2
    assert observations[0]["files"] == 3


def test_file_close_then_raise_never_recloses_reused_descriptor(source, monkeypatch):
    path = source / "src/angerona/a.py"
    owner = recovery.FileLease(path)
    descriptor = owner.fd
    real_close = os.close
    replacement = []
    calls = []
    safe_os = SimpleNamespace(**vars(recovery.os))

    def ambiguous(fd):
        calls.append(fd)
        real_close(fd)
        replacement.append(os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)))
        assert replacement[0] == descriptor
        raise OSError("closed, result unavailable")

    safe_os.close = ambiguous
    monkeypatch.setattr(recovery, "os", safe_os)
    try:
        with pytest.raises(recovery.Held, match="close could not be confirmed"):
            owner.close()
        owner.close()
        assert owner.fd == -1 and calls == [descriptor]
        assert os.fstat(replacement[0]).st_size == len(b"A = 1\n")
        assert recovery._FILE_CLOSE_HELD
        with pytest.raises(recovery.Held, match="retirement is uncertain"):
            recovery.FileLease(path)
        observations = []
        with pytest.raises(recovery.Held, match="retirement is uncertain"):
            recovery.fingerprint(source, observations)
        assert len(observations) == 1 and observations[0]["close_custody"] == "held"
    finally:
        for fd in replacement:
            real_close(fd)


def test_unknown_descriptor_close_is_one_shot_and_blocks_more_work(source, monkeypatch):
    owner = recovery.FileLease.__new__(recovery.FileLease)
    owner.fd = 123456789
    calls = []
    safe_os = SimpleNamespace(**vars(recovery.os))

    def unknown(fd):
        calls.append(fd)
        raise OSError("unknown result")

    safe_os.close = unknown
    monkeypatch.setattr(recovery, "os", safe_os)
    with pytest.raises(recovery.Held, match="close could not be confirmed"):
        owner.close()
    owner.close()
    assert calls == [123456789]
    assert recovery._FILE_CLOSE_HELD


@pytest.mark.skipif(os.name != "nt", reason="Native Windows descriptor handoff")
@pytest.mark.parametrize("close_result", [False, "raises"])
def test_failed_descriptor_handoff_requires_native_close_ack(source, monkeypatch, close_result):
    calls = []

    def create(*_args):
        return 12345

    def close(handle):
        calls.append(handle)
        if close_result == "raises":
            raise OSError("ambiguous native close")
        return False

    def fail_handoff(*_args):
        raise OSError("descriptor admission failed")

    native = SimpleNamespace(CreateFileW=create, CloseHandle=close)
    safe_ctypes = SimpleNamespace(**vars(recovery.ctypes))
    safe_ctypes.WinDLL = lambda *_args, **_kwargs: native
    monkeypatch.setattr(recovery, "ctypes", safe_ctypes)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=fail_handoff))
    with pytest.raises(recovery.Held, match="native file close could not be confirmed"):
        recovery.FileLease(source / "src/angerona/a.py")
    assert calls == [12345]
    assert recovery._FILE_CLOSE_HELD


def test_file_read_still_checks_final_named_and_opened_identity(source, monkeypatch):
    path = source / "src/angerona/a.py"
    with recovery.FileLease(path) as owner:
        safe_os = SimpleNamespace(**vars(recovery.os))
        original = os.fstat

        def changed(fd):
            value = original(fd)
            fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
            fields["st_size"] += 1
            return SimpleNamespace(**fields)

        safe_os.fstat = changed
        monkeypatch.setattr(recovery, "os", safe_os)
        with pytest.raises(recovery.Held, match="changed during reading"):
            owner.read(recovery.MAX_FILE)


def test_main_keeps_one_lock_for_time_retry_and_exposes_original_timeout(source, monkeypatch, capsys):
    now = clock(monkeypatch)
    held = [False]
    entries = []
    original = recovery.read
    reads = []

    class Store:
        def __init__(self, _root, _state):
            self.root = source

        @contextlib.contextmanager
        def locked(self):
            assert not held[0]
            entries.append(True)
            held[0] = True
            try:
                yield
            finally:
                held[0] = False

    def delayed(*args, **kwargs):
        assert held[0]
        data = original(*args, **kwargs)
        reads.append(True)
        if len(reads) == 1:
            now[0] += 31
        return data

    monkeypatch.setattr(recovery, "RecoveryStore", Store)
    monkeypatch.setattr(recovery, "read", delayed)
    assert recovery.main(["--root", str(source), "--state-root", str(source / "state"), "--action", "fingerprint"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert entries == [True] and not held[0]
    assert result["inventory_attempts"] == 2
    assert result["inventory_passes"][0]["status"] == "held"
    assert result["inventory_passes"][0]["reason"] == "time"
    assert [row["status"] for row in result["inventory_passes"][-2:]] == ["complete", "complete"]
