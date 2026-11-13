"""Inert native-query ownership tests; no OS process is opened or launched."""
from types import SimpleNamespace
import threading

import pytest

from angerona.telemetry import process_snapshot_worker as worker


class FakeNative:
    def __init__(self, identities, *, close_error=False, open_error=False):
        self.identities = iter(identities)
        self.close_error, self.open_error = close_error, open_error
        self.allocations = self.opens = 0
        self.queries, self.closes = [], []

    def open(self, pid, rights, inherit):
        self.opens += 1
        assert (pid, rights, inherit) == (42, 0x1000 | 0x100000 | 0x100 | 1, False)
        if self.open_error:
            raise RuntimeError("open failed before ownership")
        return 100

    def object_identity(self, handle):
        self.queries.append(handle)
        value = next(self.identities)
        if isinstance(value, BaseException):
            raise value
        return value

    def close(self, handle):
        self.closes.append(handle)
        assert handle == 100  # The borrowed Popen handle 900 must never close here.
        if self.close_error:
            raise RuntimeError("close outcome unknown")


def install_fake(monkeypatch, identities, *, close_error=False, open_error=False):
    from angerona.core import windows_process_lease
    native = FakeNative(identities, close_error=close_error, open_error=open_error)
    def allocate():
        native.allocations += 1
        return native
    # Replace only this module's os reference; do not change the platform used
    # by pathlib, pytest or the native adapter module.
    monkeypatch.setattr(worker, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(worker, "_PIN_CONSTRUCTOR_LOCK", threading.Lock())
    monkeypatch.setattr(worker, "_PIN_CONSTRUCTOR_QUARANTINE", None)
    monkeypatch.setattr(windows_process_lease, "_Native", allocate)
    return native


@pytest.mark.parametrize("identities,expected_queries", [
    ([RuntimeError("first identity failed")], [100]),
    ([(42, 123), RuntimeError("second identity failed")], [100, 900]),
    ([(42, 123), (42, 456)], [100, 900]),
])
def test_constructor_failure_closes_only_its_new_query_handle(monkeypatch, identities, expected_queries):
    native = install_fake(monkeypatch, identities)
    with pytest.raises((RuntimeError, worker.InventoryWorkerError)):
        worker._Pin(42, process=SimpleNamespace(_handle=900))
    assert native.queries == expected_queries
    assert native.closes == [100]
    assert worker._PIN_CONSTRUCTOR_QUARANTINE is None


@pytest.mark.parametrize("identities", [
    [RuntimeError("first identity failed")],
    [(42, 123), RuntimeError("second identity failed")],
    [(42, 123), (42, 456)],
])
def test_unknown_constructor_close_quarantines_once_and_blocks_new_allocation(monkeypatch, identities):
    native = install_fake(monkeypatch, identities, close_error=True)
    popen = SimpleNamespace(_handle=900)
    with pytest.raises(worker.InventoryCustodyCloseError, match="cleanup remains held"):
        worker._Pin(42, process=popen)
    owner = worker._PIN_CONSTRUCTOR_QUARANTINE
    assert owner is not None and owner.handle == 100
    assert owner.close_failed is True and owner.process is popen
    with pytest.raises(worker.InventoryCustodyCloseError, match="must not be retried"):
        owner.release_unadmitted()
    assert owner.retire(0.0, terminate=True) is False
    with pytest.raises(worker.InventoryCustodyCloseError, match="Prior process-pin"):
        worker._Pin(42, process=popen)
    assert native.allocations == native.opens == 1
    assert native.closes == [100]
    assert worker._PIN_CONSTRUCTOR_QUARANTINE is owner
    assert popen._handle == 900


def test_successful_pin_retains_api_and_closes_query_handle_once(monkeypatch):
    native = install_fake(monkeypatch, [(42, 123), (42, 123)])
    pin = worker._Pin(42, process=SimpleNamespace(_handle=900))
    assert pin.birth == "123" and pin.identity == (42, 123)
    assert pin.handle == 100 and pin.closed is False
    assert native.closes == []
    pin.release_unadmitted()
    pin.release_unadmitted()
    assert pin.handle is None and pin.closed is True
    assert native.closes == [100]
    assert worker._PIN_CONSTRUCTOR_QUARANTINE is None


def test_open_failure_does_not_close_a_handle_it_never_owned(monkeypatch):
    native = install_fake(monkeypatch, [], open_error=True)
    with pytest.raises(RuntimeError, match="open failed"):
        worker._Pin(42, process=SimpleNamespace(_handle=900))
    assert native.closes == []
    assert worker._PIN_CONSTRUCTOR_QUARANTINE is None
