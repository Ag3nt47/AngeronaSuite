"""One retained Core context worker; no invented peer heartbeat or deployment."""
from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import service_process_context as context
from angerona.core.werfault_guard import OwnedProcessIdentity, read_owned_processes
from angerona.core.windows_process_lease import ProcessObjectIdentity


@pytest.fixture
def owner(monkeypatch):
    value = SimpleNamespace(identity=ProcessObjectIdentity(os.getpid(), 134377000000000000,
                                                          r"C:\owned\Angerona.exe"))
    monkeypatch.setattr(context, "active_engine_custody", lambda: value)
    monkeypatch.setattr(context, "_RETIREMENT_HOLD", None)
    return value


def test_background_refresh_is_core_only_and_cached_context_expires(owner):
    calls = []
    class Cache:
        def __init__(self, expected, **kwargs):
            assert set(expected.values()) == {None}
            assert kwargs["owned_core_pid"] == os.getpid()
            assert [role for role, enabled in kwargs["enabled"].items() if enabled] == ["core"]
            with pytest.raises(PermissionError, match="does not read"):
                kwargs["reader_factory"]("core")
            self.rows = ()
        def refresh_owned_processes(self):
            calls.append(("refresh", threading.get_ident()))
            now = time.monotonic()
            self.rows = (OwnedProcessIdentity(owner.identity.pid, str(owner.identity.birth_ticks),
                owner.identity.create_time, owner.identity.image, "core", now, now + 2),)
        def owned_process_identities(self):
            return self.rows
        def mark_stopped(self):
            self.rows = ()
        def close(self):
            calls.append(("close", threading.get_ident()))
            self.rows = ()
    worker = context.ServiceProcessContext(owner, _cache_factory=Cache)
    try:
        worker.start()
        assert worker._ready.wait(3)
        rows = worker.owned_process_identities()
        assert len(rows) == 1 and rows[0].role == "core"
        assert read_owned_processes(worker.owned_process_identities, now=rows[0].observed_monotonic) == rows
        with pytest.raises(ValueError, match="stale"):
            read_owned_processes(worker.owned_process_identities, now=rows[0].expires_monotonic)
        assert all(ident != threading.get_ident() for _name, ident in calls)
        worker.request_stop()
        assert worker.owned_process_identities() == ()
    finally:
        assert worker.close()
    assert [name for name, _ident in calls].count("close") == 1
    assert not worker._thread.is_alive()


def test_partial_thread_start_is_sticky_even_before_ident_or_liveness_publication(owner, monkeypatch):
    calls = []
    class PartialThread:
        ident = None
        def __init__(self, **kwargs):
            assert kwargs["daemon"] is False
        def start(self):
            calls.append("start")
            raise RuntimeError("inert uncertain native bootstrap admission")
        def is_alive(self):
            return False  # This cannot certify that native admission never ran.
        def join(self, *_args):
            pytest.fail("unpublished native bootstrap cannot be assumed joinable")
    with monkeypatch.context() as local:
        local.setattr(context.threading, "Thread", PartialThread)
        worker = context.ServiceProcessContext(owner)
        with pytest.raises(RuntimeError, match="bootstrap admission"):
            worker.start()
        assert worker.owned_process_identities() == ()
        assert context._RETIREMENT_HOLD is worker and worker._start_failed
        for _ in range(2):
            with pytest.raises(RuntimeError, match="retirement remains unproven"):
                worker.close()
        with pytest.raises(PermissionError, match="actual admitted"):
            context.ServiceProcessContext(owner)
    assert calls == ["start"]


@pytest.mark.parametrize("failure", ["close", "pending-refresh"])
def test_stop_fence_retains_close_uncertainty_or_pending_worker_without_reopen(owner, failure):
    entered, release = threading.Event(), threading.Event()
    calls = []
    class Cache:
        def __init__(self, *_args, **_kwargs):
            pass
        def refresh_owned_processes(self):
            entered.set()
            if failure == "pending-refresh":
                assert release.wait(5)
        def owned_process_identities(self):
            return ()
        def mark_stopped(self):
            pass
        def close(self):
            calls.append("close")
            if failure == "close":
                raise OSError("inert query-handle close uncertainty")
    worker = context.ServiceProcessContext(owner, _cache_factory=Cache)
    worker.start()
    try:
        assert entered.wait(3)
        with pytest.raises(RuntimeError, match="retirement remains unproven"):
            worker.close(timeout=.01)
        assert worker.owned_process_identities() == () and context._RETIREMENT_HOLD is worker
        release.set()
        worker._thread.join(3)
        assert not worker._thread.is_alive()
        with pytest.raises(RuntimeError, match="retirement remains unproven"):
            worker.close()
        assert calls == ["close"]
    finally:
        release.set()
        worker._thread.join(3)
        worker._close_error = ""  # Only expected diagnostics from inert seams.
        worker._retirement_error = False
        worker.close()


@pytest.mark.skipif(os.name != "nt", reason="Real query-only native Core observation")
def test_actual_core_context_uses_only_query_synchronize_and_retires_its_witness(owner, monkeypatch):
    from angerona.core.windows_process_lease import _Native
    from angerona.resilience import component_status

    opened, closed = [], []
    original_open, original_close = _Native.open, _Native.close
    def open_process(native, pid, rights, inherit):
        opened.append((pid, rights, inherit))
        return original_open(native, pid, rights, inherit)
    def close_process(native, handle):
        closed.append(handle)
        return original_close(native, handle)
    monkeypatch.setattr(_Native, "open", open_process)
    monkeypatch.setattr(_Native, "close", close_process)
    monkeypatch.setattr(component_status, "_existing_private_file", lambda *_a, **_k:
                        pytest.fail("native service Core context tried a heartbeat file"))
    worker = context.ServiceProcessContext(owner)
    try:
        worker.start()
        assert worker._ready.wait(5)
        rows = read_owned_processes(worker.owned_process_identities, now=time.monotonic())
        assert len(rows) == 1 and (rows[0].pid, rows[0].role) == (os.getpid(), "core")
        assert opened == [(os.getpid(), 0x101000, False)]
        assert rows[0].birth_ticks == str(worker._cache._owned_witnesses["core"].identity.birth_ticks)
    finally:
        assert worker.close()
    assert len(closed) == 1 and worker._cache._owned_witnesses == {}
    assert worker.owned_process_identities() == () and not worker._thread.is_alive()
