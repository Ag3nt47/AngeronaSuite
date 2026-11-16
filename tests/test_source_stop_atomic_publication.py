"""STOP publication faults leave originals intact and permit a safe retry."""
from __future__ import annotations

import errno
import os

import pytest

from angerona.resilience import source_stop as stop
from test_source_stop_protocol import source as source, _context, _directory


def test_partial_write_does_not_create_fixed_stop_and_next_retry_can_commit(source, monkeypatch):
    context = _context(source)
    directory = _directory(source, context)
    actual_write = stop.os.write
    failed = False
    def partial(descriptor, raw):
        nonlocal failed
        if not failed and b'"purpose":"stop"' in raw:
            failed = True
            actual_write(descriptor, raw[:19])
            raise OSError(errno.ENOSPC, "inert partial STOP write")
        return actual_write(descriptor, raw)
    monkeypatch.setattr(stop.os, "write", partial)
    with pytest.raises(OSError, match="inert partial STOP write"):
        context.request_stop()
    assert not (directory / "stop.json").exists()
    retained = directory / stop._STOP_PENDING_NAMES[0]
    partial_bytes = retained.read_bytes()
    assert len(partial_bytes) == 19
    result = context.request_stop()
    assert context.is_stop_requested() and result["purpose"] == "stop"
    assert retained.read_bytes() == partial_bytes
    context.mark_retired()
    assert not stop._complete_closed_directory(directory), "Unknown partial evidence cannot be pruned"


def test_fsync_failure_leaves_only_pending_bytes_and_retry_reuses_valid_attempt(source, monkeypatch):
    context = _context(source)
    directory = _directory(source, context)
    actual_fsync = stop.os.fsync
    failed = False
    def fail_once(descriptor):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError(errno.EIO, "inert STOP fsync failure")
        return actual_fsync(descriptor)
    monkeypatch.setattr(stop.os, "fsync", fail_once)
    with pytest.raises(OSError, match="inert STOP fsync failure"):
        context.request_stop()
    assert not (directory / "stop.json").exists()
    pending = directory / stop._STOP_PENDING_NAMES[0]
    attempted = pending.read_bytes()
    context.request_stop()
    assert context.is_stop_requested()
    assert (directory / "stop.json").read_bytes() == attempted
    assert not pending.exists()


def test_no_replace_rename_failure_leaves_pending_attempt_and_retry_commits_it(source, monkeypatch):
    context = _context(source)
    directory = _directory(source, context)
    actual_publish = stop._publish_stop_no_replace
    failed = False
    def fail_once(*args):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError(errno.EIO, "inert STOP rename failure")
        return actual_publish(*args)
    monkeypatch.setattr(stop, "_publish_stop_no_replace", fail_once)
    with pytest.raises(OSError, match="inert STOP rename failure"):
        context.request_stop()
    assert not (directory / "stop.json").exists()
    pending = directory / stop._STOP_PENDING_NAMES[0]
    attempted = pending.read_bytes()
    context.request_stop()
    assert context.is_stop_requested()
    assert (directory / "stop.json").read_bytes() == attempted
    assert not pending.exists()
    context.mark_retired()
    assert stop._complete_closed_directory(directory)


@pytest.mark.parametrize("valid", [False, True])
def test_existing_valid_or_invalid_stop_is_never_replaced(source, monkeypatch, valid):
    context = _context(source)
    path = _directory(source, context) / "stop.json"
    if valid:
        original = context.request_stop("original operator STOP")
    else:
        path.write_bytes(b"preserve this invalid original")
    before = path.read_bytes()
    def forbidden(*_args):
        raise AssertionError("An existing STOP reached publication")
    monkeypatch.setattr(stop, "_publish_stop_no_replace", forbidden)
    if valid:
        assert context.request_stop("new reason") == original
    else:
        with pytest.raises(ValueError):
            context.request_stop("new reason")
    assert path.read_bytes() == before


@pytest.mark.parametrize("valid", [False, True])
def test_racing_existing_target_is_not_overwritten_by_no_replace_publish(source, monkeypatch, valid):
    context = _context(source)
    directory = _directory(source, context)
    path = directory / "stop.json"
    original = context.request_stop("the winning original")
    winner = path.read_bytes() if valid else b"unknown racing original"
    path.unlink()
    actual_publish = stop._publish_stop_no_replace
    def race(current, retained, held, name):
        assert not path.exists()
        path.write_bytes(winner)
        return actual_publish(current, retained, held, name)
    monkeypatch.setattr(stop, "_publish_stop_no_replace", race)
    if valid:
        assert context.request_stop("the losing attempt") == original
    else:
        with pytest.raises(ValueError):
            context.request_stop("the losing attempt")
    assert path.read_bytes() == winner


def test_unknown_pending_slots_stay_bounded_and_are_never_removed_to_force_success(source):
    context = _context(source)
    directory = _directory(source, context)
    originals = {name: ("unknown original " + name).encode() for name in stop._STOP_PENDING_NAMES}
    for name, raw in originals.items():
        (directory / name).write_bytes(raw)
    before = {path.name for path in directory.iterdir()}
    with pytest.raises(RuntimeError, match="pending slots are retained"):
        context.request_stop()
    assert {path.name for path in directory.iterdir()} == before
    assert {name: (directory / name).read_bytes() for name in originals} == originals
    assert not (directory / "stop.json").exists()


def test_pending_record_from_another_epoch_is_preserved_and_never_admitted(source):
    first = _context(source)
    first.request_stop()
    foreign = (_directory(source, first) / "stop.json").read_bytes()
    current = _context(source)
    directory = _directory(source, current)
    original = directory / stop._STOP_PENDING_NAMES[0]
    original.write_bytes(foreign)
    record = current.request_stop()
    assert record["epoch"] == current.epoch and current.is_stop_requested()
    assert original.read_bytes() == foreign


@pytest.mark.skipif(os.name == "nt", reason="POSIX hardlink publication recovery")
def test_retry_completes_only_its_valid_same_inode_hardlink_window(source, monkeypatch):
    context = _context(source)
    directory = _directory(source, context)
    calls = []
    def crash_after_link(current, retained, held, name):
        calls.append(name)
        os.link(name, "stop.json", src_dir_fd=retained.descriptor,
                dst_dir_fd=retained.descriptor, follow_symlinks=False)
        raise OSError(errno.EIO, "inert crash after no-replace link")
    monkeypatch.setattr(stop, "_publish_stop_no_replace", crash_after_link)
    with pytest.raises(OSError, match="inert crash after no-replace link"):
        context.request_stop()
    pending, target = directory / stop._STOP_PENDING_NAMES[0], directory / "stop.json"
    before = target.read_bytes()
    assert pending.stat().st_nlink == target.stat().st_nlink == 2
    assert not context.is_stop_requested()
    context.request_stop()
    assert context.is_stop_requested() and target.read_bytes() == before
    assert not pending.exists() and target.stat().st_nlink == 1
    assert calls == [stop._STOP_PENDING_NAMES[0]], "Recovery must not publish a new intent"


@pytest.mark.skipif(os.name == "nt", reason="POSIX invalid linked-original preservation")
def test_unsigned_two_link_original_is_not_treated_as_owned_publication(source):
    context = _context(source)
    directory = _directory(source, context)
    pending, target = directory / stop._STOP_PENDING_NAMES[0], directory / "stop.json"
    pending.write_bytes(b"unsigned original")
    os.link(pending, target)
    with pytest.raises(ValueError):
        context.request_stop()
    assert pending.read_bytes() == target.read_bytes() == b"unsigned original"
    assert pending.stat().st_nlink == target.stat().st_nlink == 2
    assert not context.is_stop_requested()
