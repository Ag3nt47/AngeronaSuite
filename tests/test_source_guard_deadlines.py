from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from threading import Event

import pytest

from angerona.resilience import source_guard as sg
from angerona.resilience.source_guard import (
    SourceGuard,
    SourceGuardCancelled,
    SourceGuardError,
    SourceGuardTimeout,
)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    package = tmp_path / "src" / "angerona"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"VALUE = 1\n")
    child = package / "nested"
    child.mkdir()
    (child / "worker.py").write_bytes(b"WORK = True\n")
    return tmp_path


@pytest.fixture
def clock(monkeypatch):
    value = [100.0]
    monkeypatch.setattr(sg.time, "monotonic", lambda: value[0])
    return value


@pytest.mark.parametrize("deadline", [True, False, 0, -1, float("nan"), float("inf"),
                                     -float("inf"), "101", object(), 10 ** 1000])
def test_malformed_deadlines_fail_before_observation(source, monkeypatch, deadline):
    monkeypatch.setattr(sg, "_observe", lambda *_a, **_k: pytest.fail("source was read"))
    with pytest.raises(SourceGuardError, match="deadline is malformed"):
        SourceGuard.capture(source, deadline=deadline)


@pytest.mark.parametrize("deadline", [99, 100, 100.0])
def test_expired_deadline_fails_before_custody_or_inventory(source, clock, monkeypatch, deadline):
    monkeypatch.setattr(sg, "_hold_plain_directories", lambda *_a: pytest.fail("custody started"))
    with pytest.raises(SourceGuardTimeout):
        SourceGuard.capture(source, deadline=deadline)


def test_default_callers_use_no_clock_and_original_private_call_shapes(source, monkeypatch):
    monkeypatch.setattr(sg.time, "monotonic", lambda: pytest.fail("default queried clock"))
    observe, inventory = sg._observe, sg._inventory
    calls = []

    def original_inventory_shape(root):
        calls.append("inventory")
        return inventory(root)

    def original_observe_shape(root):
        calls.append("observe")
        return observe(root)

    monkeypatch.setattr(sg, "_observe", original_observe_shape)
    monkeypatch.setattr(sg, "_inventory", original_inventory_shape)
    guard = SourceGuard.capture(source)
    assert guard.check().ok
    assert calls == ["observe", "inventory", "inventory"] * 2


def test_opt_in_success_preserves_both_inventories_and_digest(source, clock, monkeypatch):
    original, calls = sg._inventory, []
    expected = SourceGuard.capture(source)

    def counted(root, **kwargs):
        calls.append(root)
        return original(root, **kwargs)

    monkeypatch.setattr(sg, "_inventory", counted)
    actual = SourceGuard.capture(source, expected.digest, deadline=101, check_cancelled=lambda: False)
    assert actual == expected
    assert calls == [source, source]


@pytest.mark.parametrize("inventory_number", [1, 2])
def test_deadline_after_either_inventory_cannot_return_seal(source, clock, monkeypatch, inventory_number):
    original, calls = sg._inventory, []

    def measured(root, **kwargs):
        result = original(root, **kwargs)
        calls.append(root)
        if len(calls) == inventory_number:
            clock[0] = 101
        return result

    monkeypatch.setattr(sg, "_inventory", measured)
    with pytest.raises(SourceGuardTimeout):
        SourceGuard.capture(source, deadline=101)
    assert len(calls) == inventory_number


def test_deadline_during_directory_enumeration_stops_before_file_read(source, clock, monkeypatch):
    original = sg.os.scandir

    @contextmanager
    def expired_entry(directory):
        with original(directory) as entries:
            def values():
                for entry in entries:
                    clock[0] = 101
                    yield entry
            yield values()

    monkeypatch.setattr(sg.os, "scandir", expired_entry)
    monkeypatch.setattr(sg, "_read_bytes", lambda *_a, **_k: pytest.fail("file read after expiry"))
    with pytest.raises(SourceGuardTimeout):
        SourceGuard.capture(source, deadline=101)


def test_expiry_after_file_read_does_not_hash_or_read_next_file(source, clock, monkeypatch):
    original, calls = sg._read_bytes, []

    def expire_after_read(path, *, root):
        raw = original(path, root=root)
        calls.append(path)
        clock[0] = 101
        return raw

    monkeypatch.setattr(sg, "_read_bytes", expire_after_read)
    monkeypatch.setattr(sg.hashlib, "sha256", lambda *_a: pytest.fail("hash after expired read"))
    with pytest.raises(SourceGuardTimeout):
        SourceGuard.capture(source, deadline=101)
    assert len(calls) == 1


def test_expiry_after_serialization_prevents_final_digest(source, clock, monkeypatch):
    original_dump, original_hash = sg.json.dumps, sg.hashlib.sha256
    hashed = []

    def expire(*args, **kwargs):
        encoded = original_dump(*args, **kwargs)
        clock[0] = 101
        return encoded

    def record(raw):
        hashed.append(raw)
        return original_hash(raw)

    monkeypatch.setattr(sg.json, "dumps", expire)
    monkeypatch.setattr(sg.hashlib, "sha256", record)
    with pytest.raises(SourceGuardTimeout):
        SourceGuard.capture(source, deadline=101)
    assert len(hashed) == 2
    assert all(not raw.startswith(sg._DOMAIN) for raw in hashed)


@pytest.mark.parametrize("operation", ["capture", "check"])
def test_final_return_fence_rejects_expiry_after_observation(source, clock, monkeypatch, operation):
    guard = SourceGuard.capture(source)
    original = sg._observe

    def expire_on_return(root, **kwargs):
        result = original(root, **kwargs)
        clock[0] = 101
        return result

    monkeypatch.setattr(sg, "_observe", expire_on_return)
    if operation == "capture":
        with pytest.raises(SourceGuardTimeout):
            SourceGuard.capture(source, deadline=101)
    else:
        result = guard.check(deadline=101)
        assert not result.ok and result.state == "unavailable" and result.digest == ""
        assert "deadline expired" in result.reason


def test_stop_cancellation_after_read_releases_original_contexts_once(source, monkeypatch):
    stop = Event()
    hold, read = sg._hold_plain_directories, sg._read_bytes
    entered, closed = [], []

    @contextmanager
    def tracked(*args):
        token = object()
        with hold(*args):
            entered.append(token)
            try:
                yield
            finally:
                closed.append(token)

    def stop_after_read(path, *, root):
        raw = read(path, root=root)
        stop.set()
        return raw

    monkeypatch.setattr(sg, "_hold_plain_directories", tracked)
    monkeypatch.setattr(sg, "_read_bytes", stop_after_read)
    monkeypatch.setattr(sg.time, "monotonic", lambda: pytest.fail("cancel-only queried clock"))
    with pytest.raises(SourceGuardCancelled):
        SourceGuard.capture(source, check_cancelled=stop.is_set)
    assert entered and set(entered) == set(closed)
    assert len(entered) == len(closed) == len(set(closed))


def test_already_cancelled_never_starts_source_io(source, monkeypatch):
    monkeypatch.setattr(sg, "_observe", lambda *_a, **_k: pytest.fail("source was read"))
    with pytest.raises(SourceGuardCancelled):
        SourceGuard.capture(source, check_cancelled=lambda: True)


@pytest.mark.parametrize("callback", [False, True, 1, "callback"])
def test_noncallable_cancellation_is_rejected(source, callback):
    with pytest.raises(SourceGuardError, match="cancellation check is malformed"):
        SourceGuard.capture(source, check_cancelled=callback)


@pytest.mark.parametrize("value", [None, 0, 1, "yes", object()])
def test_nonboolean_callback_result_never_admits_source(source, value):
    with pytest.raises(SourceGuardError, match="cancellation check is malformed"):
        SourceGuard.capture(source, check_cancelled=lambda: value)


def test_callback_failure_is_unavailable_without_private_error_text(source):
    guard = SourceGuard.capture(source)

    def unavailable():
        raise RuntimeError("private callback secret")

    result = guard.check(check_cancelled=unavailable)
    assert not result.ok and result.state == "unavailable" and result.digest == ""
    assert result.reason == "Execution source cancellation check is unavailable"


@pytest.mark.parametrize("current", [True, None, -1, float("nan"), float("inf"), 10 ** 1000])
def test_invalid_clock_never_admits_source(source, monkeypatch, current):
    monkeypatch.setattr(sg.time, "monotonic", lambda: current)
    with pytest.raises(SourceGuardError, match="deadline clock is unavailable"):
        SourceGuard.capture(source, deadline=101)


def test_failed_clock_is_fixed_unavailable(source, monkeypatch):
    def unavailable():
        raise RuntimeError("private clock secret")

    monkeypatch.setattr(sg.time, "monotonic", unavailable)
    with pytest.raises(SourceGuardError, match="^Execution source deadline clock is unavailable$"):
        SourceGuard.capture(source, deadline=101)


def test_clock_regression_after_read_cannot_admit_source(source, clock, monkeypatch):
    original = sg._read_bytes

    def regress(path, *, root):
        raw = original(path, root=root)
        clock[0] = 99
        return raw

    monkeypatch.setattr(sg, "_read_bytes", regress)
    with pytest.raises(SourceGuardError, match="deadline clock is unavailable"):
        SourceGuard.capture(source, deadline=101)


def test_read_identity_failure_is_not_overwritten_by_late_cancellation(source, monkeypatch):
    stop = Event()
    original = sg._read_bytes

    def change_after_read(path, *, root):
        raw = original(path, root=root)
        path.write_bytes(raw + b"# changed\n")
        stop.set()
        return raw

    monkeypatch.setattr(sg, "_read_bytes", change_after_read)
    with pytest.raises(SourceGuardError, match="changed during observation") as raised:
        SourceGuard.capture(source, check_cancelled=stop.is_set)
    assert type(raised.value) is SourceGuardError


def test_native_custody_failure_is_not_overwritten_by_late_cancellation(source, monkeypatch):
    stop = Event()

    def failure(*_args, **_kwargs):
        stop.set()
        raise PermissionError("private custody path")

    monkeypatch.setattr(sg, "_read_bytes", failure)
    with pytest.raises(SourceGuardError, match="custody or availability is unverified") as raised:
        SourceGuard.capture(source, check_cancelled=stop.is_set)
    assert type(raised.value) is SourceGuardError
    assert isinstance(raised.value.__cause__, PermissionError)


def test_parent_digest_mismatch_is_not_overwritten_at_final_cancellation(source, monkeypatch):
    stop = Event()
    original = sg._observe

    def cancel_after_observe(root, **kwargs):
        result = original(root, **kwargs)
        stop.set()
        return result

    monkeypatch.setattr(sg, "_observe", cancel_after_observe)
    with pytest.raises(SourceGuardError, match="parent session seal") as raised:
        SourceGuard.capture(source, "0" * 64, check_cancelled=stop.is_set)
    assert type(raised.value) is SourceGuardError


def test_cancelled_check_does_not_rebaseline_or_return_old_digest(source):
    guard = SourceGuard.capture(source)
    original = guard.digest
    result = guard.check(check_cancelled=lambda: True)
    assert not result.ok and result.state == "unavailable" and result.digest == ""
    assert guard.digest == original
    assert guard.check().ok


@pytest.mark.parametrize("late_signal", ["cancel", "expiry"])
def test_known_changed_receipt_survives_late_cancel_or_expiry(source, clock, monkeypatch, late_signal):
    guard = SourceGuard.capture(source)
    changed = source / "src" / "angerona" / "__init__.py"
    changed.write_bytes(b"VALUE = 2\n")
    original, stop = sg._observe, Event()

    def signal_after_observation(root, **kwargs):
        result = original(root, **kwargs)
        if late_signal == "cancel":
            stop.set()
        else:
            clock[0] = 101
        return result

    monkeypatch.setattr(sg, "_observe", signal_after_observation)
    result = guard.check(deadline=101, check_cancelled=stop.is_set)
    assert not result.ok and result.state == "changed"
    assert result.changed == ("src/angerona/__init__.py",) and result.changed_count == 1
    assert result.digest and result.digest != guard.digest


@pytest.mark.parametrize("operation", ["capture", "check"])
def test_valid_source_cannot_pass_late_cancellation(source, monkeypatch, operation):
    guard = SourceGuard.capture(source)
    original, stop = sg._observe, Event()

    def cancel_after_observation(root, **kwargs):
        result = original(root, **kwargs)
        stop.set()
        return result

    monkeypatch.setattr(sg, "_observe", cancel_after_observation)
    if operation == "capture":
        with pytest.raises(SourceGuardCancelled):
            SourceGuard.capture(source, check_cancelled=stop.is_set)
    else:
        result = guard.check(check_cancelled=stop.is_set)
        assert not result.ok and result.state == "unavailable" and result.digest == ""
        assert "was cancelled" in result.reason
