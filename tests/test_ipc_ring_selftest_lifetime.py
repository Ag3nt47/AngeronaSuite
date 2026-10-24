"""Real ring resource closure before self-test directory removal.

All fixture files and explicit synthetic keys belong to tmp_path. The captured
cleanup state precedes the test's independent failure-safe resource cleanup.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.resilience import ipc_ring


class _InjectedBodyFailure(RuntimeError):
    pass


@pytest.fixture
def captured_selftest(tmp_path, monkeypatch):
    real_writer = ipc_ring.RingWriter
    real_reader = ipc_ring.RingReader
    real_mkdtemp = tempfile.mkdtemp
    real_rmtree = shutil.rmtree
    state = SimpleNamespace(
        rings=[], directories=[], removals=[], reader_attempts=0,
        reject_reader=False, fail_body=None, write_calls=0, read_calls=0,
    )

    def close_captured():
        # Test safety only: never mistake this fallback for product retirement.
        for _kind, ring in reversed(state.rings):
            try:
                if not ring._mm.closed:
                    ring._mm.close()
            finally:
                if not ring._f.closed:
                    ring._f.close()

    def private_directory(*args, **kwargs):
        assert args == () and kwargs == {"prefix": "ring_selftest_"}
        directory = Path(real_mkdtemp(prefix="ring_selftest_", dir=tmp_path))
        state.directories.append(directory)
        return str(directory)

    def inspected_removal(path, *args, **kwargs):
        target = Path(path)
        assert args == () and kwargs == {"ignore_errors": True}
        assert target in state.directories and target.parent == tmp_path
        observed = [
            (kind, ring._mm.closed, ring._f.closed)
            for kind, ring in state.rings
        ]
        state.removals.append((target, observed))
        try:
            assert observed, "self-test reached removal without an owned ring"
            assert all(mapping and file for _kind, mapping, file in observed), (
                "directory removal preceded actual ring closure", observed,
            )
        finally:
            # The pre-cleanup observations above remain authoritative even if
            # this test runs against the old leaking-order implementation.
            close_captured()
            real_rmtree(target, ignore_errors=True)

    def writer(*args, **kwargs):
        assert kwargs.get("key") == b"r" * 32
        ring = real_writer(*args, **kwargs)
        state.rings.append(("writer", ring))
        original_write = ring.write

        def observed_write(*write_args, **write_kwargs):
            result = original_write(*write_args, **write_kwargs)
            state.write_calls += 1
            if state.fail_body == "write" and state.write_calls == 3:
                raise _InjectedBodyFailure("after genuine third write")
            return result

        monkeypatch.setattr(ring, "write", observed_write)
        return ring

    def reader(*args, **kwargs):
        assert kwargs.get("key") == b"r" * 32
        state.reader_attempts += 1
        if state.reject_reader:
            # Real constructor rejection occurs before it acquires a file/map.
            # This does not simulate an internal post-acquisition init failure.
            kwargs = dict(kwargs, key=b"invalid")
        ring = real_reader(*args, **kwargs)
        state.rings.append(("reader", ring))
        original_read = ring.read_batch

        def observed_read(*read_args, **read_kwargs):
            result = original_read(*read_args, **read_kwargs)
            state.read_calls += 1
            if state.fail_body == "read" and state.read_calls == 1:
                raise _InjectedBodyFailure("after genuine first read")
            return result

        monkeypatch.setattr(ring, "read_batch", observed_read)
        return ring

    def no_host_key(*args, **kwargs):
        pytest.fail("self-test attempted to acquire a host ring key")

    monkeypatch.setattr(tempfile, "mkdtemp", private_directory)
    monkeypatch.setattr(shutil, "rmtree", inspected_removal)
    monkeypatch.setattr(ipc_ring, "RingWriter", writer)
    monkeypatch.setattr(ipc_ring, "RingReader", reader)
    monkeypatch.setattr(ipc_ring, "_load_or_create_key", no_host_key)
    try:
        yield state
    finally:
        close_captured()
        for directory in state.directories:
            assert directory.parent == tmp_path
            real_rmtree(directory, ignore_errors=True)
        assert all(ring._mm.closed and ring._f.closed for _kind, ring in state.rings)
        assert all(not directory.exists() for directory in state.directories)


def test_selftest_normal_result_closes_real_rings_before_directory_removal(captured_selftest):
    state = captured_selftest
    assert ipc_ring.self_test() == (
        True,
        "ring round-trip + overwrite-oldest/drop-accounting + oversize rejection verified",
    )
    assert state.write_calls == 26 and state.read_calls == 2
    assert state.reader_attempts == 1
    assert len(state.removals) == len(state.directories) == 1
    directory, observed = state.removals[0]
    assert observed == [("writer", True, True), ("reader", True, True)]
    assert not directory.exists()


def test_reader_constructor_rejection_closes_already_owned_writer(captured_selftest):
    state = captured_selftest
    state.reject_reader = True
    with pytest.raises(ipc_ring.FrameError, match="exactly 32 bytes"):
        ipc_ring.self_test()
    assert state.reader_attempts == 1
    assert state.write_calls == state.read_calls == 0
    assert len(state.removals) == 1
    directory, observed = state.removals[0]
    assert observed == [("writer", True, True)]
    assert not directory.exists()


@pytest.mark.parametrize("stage", ["write", "read"], ids=["after-third-write", "after-first-read"])
def test_body_failure_closes_both_real_rings_before_removal(captured_selftest, stage):
    state = captured_selftest
    state.fail_body = stage
    with pytest.raises(_InjectedBodyFailure, match="after genuine"):
        ipc_ring.self_test()
    assert state.write_calls == (3 if stage == "write" else 5)
    assert state.read_calls == (0 if stage == "write" else 1)
    assert state.reader_attempts == 1
    assert len(state.removals) == 1
    directory, observed = state.removals[0]
    assert observed == [("writer", True, True), ("reader", True, True)]
    assert not directory.exists()
