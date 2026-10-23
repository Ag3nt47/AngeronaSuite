"""Synchronous lifecycle changes from snapshot callbacks must stop admission."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication, QWidget
from shiboken6 import delete, isValid

from angerona.gui import async_snapshot


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance()
    owns = application is None
    if owns:
        application = QApplication([])
    previous_quit_on_last_window = application.quitOnLastWindowClosed()
    application.setQuitOnLastWindowClosed(False)
    try:
        yield application
    finally:
        if owns:
            application.shutdown()
            assert QApplication.instance() is None
        else:
            assert QApplication.instance() is application
            application.setQuitOnLastWindowClosed(previous_quit_on_last_window)


@pytest.fixture
def owned_threads(monkeypatch):
    """Retain every real thread even when an older request loses its reference."""
    workers = []

    def create(*args, **kwargs):
        worker = threading.Thread(*args, **kwargs)
        workers.append(worker)
        return worker

    # Replace only this module's reference; the stdlib Thread is unchanged.
    monkeypatch.setattr(async_snapshot, "threading", SimpleNamespace(
        Event=threading.Event, Thread=create,
    ))
    return workers


class _TimerWitness:
    """Observe request's native timer writes while retaining the real QTimer."""

    def __init__(self, timer):
        self.native = timer
        self.writes = []

    def setInterval(self, interval):
        self.writes.append(("setInterval", interval))
        self.native.setInterval(interval)

    def start(self):
        self.writes.append(("start",))
        self.native.start()

    def stop(self):
        self.native.stop()

    def interval(self):
        return self.native.interval()


def _transition(action, reader, owner):
    if action == "close":
        reader.close()
    elif action == "delete":
        delete(owner)
        assert not isValid(owner)
    else:
        assert action == "pause"
        reader.pause()


def _settle(reader):
    deadline = time.monotonic() + 3
    while reader.busy and time.monotonic() < deadline:
        reader._poll()
        time.sleep(0.001)
    assert not reader.busy


def _dispose(reader, owner, workers, release):
    release.set()
    reader.close()
    for worker in workers:
        if worker.ident is not None:
            worker.join(2)
        assert not worker.is_alive(), "owned inert snapshot worker did not retire"
    if isValid(owner):
        delete(owner)
    assert not isValid(owner)


@pytest.mark.parametrize("action", ["close", "delete", "pause"])
def test_prepare_lifecycle_change_refuses_worker_and_timer(app, owned_threads, action):
    owner = QWidget()
    calls, values, statuses = [], [], []
    release = threading.Event()

    def read():
        calls.append("read")
        return 7

    def prepare():
        calls.append("prepare")
        if len(calls) == 1:
            _transition(action, reader, owner)
        return read

    reader = async_snapshot.AsyncSnapshot(
        owner, prepare, values.append, name="PrepareReentrancyFixture", status=statuses.append,
    )
    witness = _TimerWitness(reader._timer)
    reader._timer = witness
    try:
        reader.request()
        assert calls == ["prepare"]
        assert owned_threads == []
        assert reader.thread is None
        assert not reader.busy
        assert witness.writes == []
        assert statuses == [] and values == []
        reader.request()
        assert owned_threads == [] and calls == ["prepare"]
        if action == "pause":
            assert reader._paused and not witness.native.isActive()
            reader.resume()
            reader.request()
            _settle(reader)
            assert calls == ["prepare", "prepare", "read"]
            assert values == [7]
            assert statuses == ["updating", "current"]
            assert len(owned_threads) == 1 and reader.thread is owned_threads[0]
        else:
            assert reader._closed and reader._stopped.is_set()
    finally:
        _dispose(reader, owner, owned_threads, release)


@pytest.mark.parametrize("action", ["close", "delete", "pause"])
def test_updating_status_lifecycle_change_preserves_owned_reader(app, owned_threads, action):
    owner = QWidget()
    entered, release = threading.Event(), threading.Event()
    values, statuses = [], []

    def read():
        entered.set()
        assert release.wait(4)
        return 9

    def status(state):
        statuses.append(state)
        if state == "updating" and len(statuses) == 1:
            assert entered.wait(1), "owned inert reader did not enter"
            assert len(owned_threads) == 1 and reader.thread is owned_threads[0]
            assert owned_threads[0].is_alive()
            _transition(action, reader, owner)

    reader = async_snapshot.AsyncSnapshot(
        owner, lambda: read, values.append, name="StatusReentrancyFixture", status=status,
    )
    witness = _TimerWitness(reader._timer)
    reader._timer = witness
    try:
        reader.request()
        assert statuses == ["updating"] and values == []
        assert witness.writes == []
        assert len(owned_threads) == 1 and reader.thread is owned_threads[0]
        assert owned_threads[0].is_alive()
        if action == "pause":
            assert reader._paused and reader.busy and not witness.native.isActive()
            release.set()
            reader.resume()
            _settle(reader)
            assert values == []  # The paused generation is stale.
            reader.request()
            _settle(reader)
            assert values == [9]
            assert statuses == ["updating", "updating", "current"]
            assert len(owned_threads) == 1  # Reuse the same owned reader.
        else:
            assert reader._closed and reader._stopped.is_set()
            release.set()
            owned_threads[0].join(2)
            assert not owned_threads[0].is_alive()
            assert values == [] and reader._results.empty()
    finally:
        _dispose(reader, owner, owned_threads, release)


@pytest.mark.parametrize("with_status", [False, True])
def test_normal_callbacks_still_deliver_and_reuse_one_reader(app, owned_threads, with_status):
    owner = QWidget()
    values, statuses = [], []
    release = threading.Event()
    reader = async_snapshot.AsyncSnapshot(
        owner, lambda: lambda: 11, values.append, name="NormalReentrancyControl",
        status=statuses.append if with_status else None,
    )
    try:
        for _ in range(2):
            reader.request()
            _settle(reader)
        assert values == [11, 11]
        assert statuses == (["updating", "current"] * 2 if with_status else [])
        assert len(owned_threads) == 1 and reader.thread is owned_threads[0]
        assert reader.thread.is_alive()
        assert not reader._timer.isActive()
    finally:
        _dispose(reader, owner, owned_threads, release)
