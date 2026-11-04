"""Memory-only exact owner holds are distinct from actual thread retirement."""
import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QWidget

from angerona.gui.shutdown_retirement import RetainedCustody, RetainedWorker, ShutdownRetirement


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def _wait(app, predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(.005)
    raise AssertionError("Exact STOP fixture did not settle")


def test_dead_thread_does_not_release_lease_or_delay_critical_owned_cleanup(app, tmp_path):
    owner, released, critical = QWidget(), threading.Event(), threading.Event()
    exact = object()
    worker = threading.Thread(target=lambda: None)
    worker.start()
    worker.join(3)
    cleanup, final, diagnostics = [], [], []
    hold = RetainedCustody("exact-session-lease", exact, released.is_set)
    retirement = ShutdownRetirement(owner,
        workers=lambda: (RetainedWorker("retired-session-worker", worker, True),),
        custody=lambda: (hold,), critical=critical.set, cleanup=lambda: cleanup.append("stores"),
        finish=final.append, data_root=tmp_path,
        diagnostic_writer=lambda _root, row: diagnostics.append(row))
    retirement.start()
    try:
        _wait(app, critical.is_set)
        retirement.poll()
        assert not cleanup and not final
        assert retirement._payload("stopping")["pending_custody"] == ["exact-session-lease"]
        assert retirement._discovery_error == ""
        released.set()
        _wait(app, lambda: bool(final))
        assert cleanup == ["stores"] and final[0]["state"] == "retired"
        assert not final[0]["pending_custody"] and final[0]["forced"] is False
    finally:
        released.set()
        _wait(app, lambda: retirement._cleanup_thread is None or not retirement._cleanup_thread.is_alive())
        owner.close()


@pytest.mark.parametrize("label", ["lease-active", "reservation-active", "retirement-held", "owner-pending"])
def test_custody_timeout_is_explicitly_incomplete_without_store_cleanup(app, tmp_path, label):
    owner, exact, clock = QWidget(), object(), [0.0]
    cleanup, final = [], []
    hold = RetainedCustody(label, exact, lambda: False)
    retirement = ShutdownRetirement(owner, workers=lambda: (), custody=lambda: (hold,),
        cleanup=lambda: cleanup.append("unexpected"), finish=final.append, data_root=tmp_path,
        clock=lambda: clock[0], timeout=.1,
        diagnostic_writer=lambda _root, _row: None)
    retirement.start()
    try:
        clock[0] = .2
        retirement.poll()
        _wait(app, lambda: bool(final))
        assert not cleanup and final[0]["state"] == "forced-incomplete"
        assert final[0]["forced"] is True and final[0]["pending_workers"] == []
        assert final[0]["pending_custody"] == [label]
        assert final[0]["discovery_error"] == ""
    finally:
        _wait(app, lambda: retirement._diagnostic_thread is None or not retirement._diagnostic_thread.is_alive())
        owner.close()


def test_unknown_custody_can_later_prove_release_without_permanent_discovery_error(app, tmp_path):
    owner, exact, ready = QWidget(), object(), threading.Event()
    final, cleanup = [], []
    def released():
        if not ready.is_set():
            raise RuntimeError("Cache not ready yet")
        return True
    retirement = ShutdownRetirement(owner, workers=lambda: (),
        custody=lambda: (RetainedCustody("same-owner", exact, released),),
        cleanup=lambda: cleanup.append("stores"), finish=final.append, data_root=tmp_path,
        diagnostic_writer=lambda _root, _row: None)
    retirement.start()
    try:
        retirement.poll()
        assert not cleanup and retirement._discovery_error == ""
        ready.set()
        _wait(app, lambda: bool(final))
        assert final[0]["state"] == "retired" and cleanup == ["stores"]
    finally:
        ready.set()
        _wait(app, lambda: retirement._cleanup_thread is None or not retirement._cleanup_thread.is_alive())
        owner.close()
