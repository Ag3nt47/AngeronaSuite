"""Actual Qt Eco generations; no live suite, process actions or retirement stubs."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThread
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton
from shiboken6 import isValid

from angerona.core.eco_wakeup import EcoWakeupWorker
from angerona.core.module_base import BaseModule
from angerona.gui import main_window
from angerona.gui import native_retirement as native
from angerona.gui.shutdown_retirement import RetainedWorker, ShutdownRetirement


def until(predicate, timeout=5):
    end = time.monotonic() + timeout
    while not predicate() and time.monotonic() < end:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


class _Button(QPushButton):
    def set_full_label(self, value):
        self.setText(value)


class _Module(BaseModule):
    def __init__(self, name):
        super().__init__()
        self.name = name
        self._chill_paused = True

    def run(self):
        self.mark_cycle_complete()
        self.generation_stop_event().wait(10)


class _Owner(QMainWindow):
    _wake_chill_modules = main_window.MainWindow._wake_chill_modules
    _on_eco_worker_retired = main_window.MainWindow._on_eco_worker_retired
    _resume_pending_chill_wake = main_window.MainWindow._resume_pending_chill_wake
    _on_eco_module_ready = main_window.MainWindow._on_eco_module_ready
    _on_eco_wakeup_complete = main_window.MainWindow._on_eco_wakeup_complete
    _retained_shutdown_workers = main_window.MainWindow._retained_shutdown_workers

    def __init__(self, modules, starter=None):
        super().__init__()
        self._termination_started = False
        self._eco_worker = None
        self._wake_retry_worker = None
        self._pending_chill_wake = None
        self._eco_wake_epoch = 0
        self._eco_on = True
        self._eco_paused = [module.name for module in modules]
        self._ECO_HEAVY_MODULES = tuple(self._eco_paused)
        self._CHILL_USER_ONLY_MODULES = set()
        self._pending_simulation_cfg = None
        self._aar_report_threads = {}
        self.calls, self.logs = [], []
        self.eco_btn = _Button(self)
        self.console = SimpleNamespace(_append=self.logs.append)
        self.run_spinner = SimpleNamespace(start=lambda *_args: None,
            finish=lambda *_args: None, set_progress=lambda *_args: None)

        def start(module):
            if starter is not None:
                starter(module)
            module.start()
            self.calls.append(module.name)
            return True  # Controlled module admission only; no retirement proof.

        self.manager = SimpleNamespace(modules={module.name: module for module in modules},
            is_enabled=lambda _name: True, start_if_enabled=start)
        self.runtime = []

    def _apply_chill_throttles(self, value):
        self.runtime.append(("throttle", value))

    def _set_chill_runtime(self, value):
        self.runtime.append(("runtime", value))  # Never contact the host AI service.

    def _shutdown_view_owners(self):
        return (self,)


@pytest.fixture
def qt():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def owned(qt, monkeypatch):
    workers, modules, owners = [], [], []
    delayed, blocked_returns = set(), set()

    class ControlledEco(EcoWakeupWorker):
        def __init__(self, current, **kwargs):
            super().__init__(current, health_timeout=1, min_settle=0, poll_interval=.02, **kwargs)
            self.body_complete = threading.Event()
            self.allow_return = threading.Event()
            if len(workers) not in blocked_returns:
                self.allow_return.set()
            self.allow_native_proof = threading.Event()
            if len(workers) not in delayed:
                self.allow_native_proof.set()
            workers.append(self)

        def run(self):
            super().run()
            self.body_complete.set()
            assert self.allow_return.wait(5), "Fixture must release its actual Qt run return"

        def wait(self, milliseconds=0):
            # Model an absent native acknowledgement, never invent a True one.
            return super().wait(milliseconds) if self.allow_native_proof.is_set() else False

    monkeypatch.setattr(main_window, "EcoWakeupWorker", ControlledEco)

    def make(names=("first",), starter=None):
        current = [_Module(name) for name in names]
        modules.extend(current)
        owner = _Owner(current, starter)
        owners.append(owner)
        return owner

    yield SimpleNamespace(make=make, workers=workers, delayed=delayed,
                          blocked_returns=blocked_returns)
    for owner in owners:
        owner._termination_started = True
        owner._pending_chill_wake = None
    for worker in workers:
        worker.allow_return.set()
        worker.allow_native_proof.set()
        if isValid(worker):
            worker.cancel()
            assert QThread.wait(worker, 3000)
            native.poll_native_retirement(worker)
    until(lambda: all(native.native_retirement_proven(worker) for worker in workers))
    for module in modules:
        module.stop()
        if module._thread is not None:
            module._thread.join(3)
            assert not module._thread.is_alive()
    for owner in owners:
        owner.close()
        owner.deleteLater()


def _stop(owner, tmp_path, workers=None):
    finished, cleanup, diagnostics = [], [], []
    owner._termination_started = True
    coordinator = ShutdownRetirement(owner,
        workers=workers if workers is not None else owner._retained_shutdown_workers,
        cleanup=lambda: cleanup.append("stores may close"), finish=finished.append,
        data_root=tmp_path, diagnostic_writer=lambda _root, row: diagnostics.append(row))
    coordinator.start()
    return coordinator, finished, cleanup, diagnostics


def _delete_proven(worker):
    assert native.native_retirement_proven(worker)
    if isValid(worker):
        QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
    assert not isValid(worker)


def test_completed_deleted_eco_keeps_real_proof_for_saved_stop_record(owned, tmp_path):
    owner = owned.make()
    assert owner._wake_chill_modules(auto=False)
    worker = owner._eco_worker
    rows = owner._retained_shutdown_workers()
    row = next(row for row in rows if row.worker is worker)
    assert row.retirement_proof is native.poll_native_retirement
    until(lambda: native.native_retirement_proven(worker))
    assert owner._eco_worker is None
    _delete_proven(worker)
    coordinator, finished, cleanup, diagnostics = _stop(owner, tmp_path, lambda: (row,))
    until(lambda: bool(finished))
    assert cleanup == ["stores may close"]
    assert finished[0]["state"] == "retired" and finished[0]["forced"] is False
    assert finished[0]["pending_workers"] == [] and diagnostics[-1]["state"] == "retired"
    assert coordinator._retained[id(worker)].worker is worker
    assert native.poll_native_retirement(worker) is True


def test_stop_created_before_native_ack_preserves_custody_through_qobject_deletion(owned, tmp_path):
    owned.delayed.add(0)
    owned.blocked_returns.add(0)
    owner = owned.make()
    assert owner._wake_chill_modules(auto=False)
    worker = owner._eco_worker
    until(worker.body_complete.is_set)
    assert worker.isRunning() and not QThread.wait(worker, 0)
    coordinator, finished, cleanup, _diagnostics = _stop(owner, tmp_path)
    assert owner._eco_worker is worker and not finished and not cleanup
    worker.allow_return.set()
    until(worker.isFinished)
    assert QThread.wait(worker, 0) is True  # Actual underlying Qt worker returned.
    assert not worker.wait(0) and not native.poll_native_retirement(worker)
    assert owner._eco_worker is worker and cleanup == [] and finished == []
    worker.deleteLater()  # Existing coordinator must intercept unproved deletion.
    QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
    assert isValid(worker) and not native.native_retirement_proven(worker)
    retained = coordinator._deferred_native_delete[id(worker)]
    assert retained.type() == QEvent.Type.DeferredDelete
    # Repeated producer requests cannot allocate more native events or grant
    # retirement. The exact first clone remains bounded and retained.
    worker.deleteLater()
    QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
    assert coordinator._deferred_native_delete[id(worker)] is retained
    assert isValid(worker) and not native.native_retirement_proven(worker)
    worker.allow_native_proof.set()
    assert native.poll_native_retirement(worker)
    assert owner._eco_worker is None
    row = coordinator._retained[id(worker)]
    assert coordinator._retirement_proven(row) is True
    assert id(worker) in coordinator._native_proven  # Existing pre-added proof path.
    coordinator.poll()  # Real functional owner replays its held native event.
    assert id(worker) not in coordinator._deferred_native_delete
    assert id(worker) in coordinator._deferred_delete_posted
    _delete_proven(worker)
    until(lambda: bool(finished))
    assert finished[0]["state"] == "retired" and not finished[0]["forced"]
    assert cleanup == ["stores may close"] and not finished[0]["pending_workers"]
    assert coordinator._retained[id(worker)].retirement_proof is native.poll_native_retirement


def test_cancelled_admitted_start_blocks_new_generation_until_exact_native_settlement(owned):
    entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()
    cancel_thread = None

    def admitted_start(module):
        if module.name == "first":
            entered.set()
            assert release.wait(5), "Fixture must release its exact admitted start"
        else:
            assert native.native_retirement_proven(owned.workers[0])

    owned.delayed.add(1)  # Keep the genuine replacement retained for stale-delivery assertions.
    owner = owned.make(("first", "second"), admitted_start)
    try:
        assert owner._wake_chill_modules(auto=False)
        old = owner._eco_worker
        assert entered.wait(3)
        cancel_thread = threading.Thread(target=lambda: (old.cancel(), cancelled.set()),
                                         name="inert-eco-cancel")
        cancel_thread.start()
        until(lambda: old._abort is True)
        assert not cancelled.is_set() and owner.calls == []
        assert owner._wake_chill_modules(auto=False)
        assert owner._eco_worker is old and len(owned.workers) == 1
        release.set()
        until(cancelled.is_set)
        cancel_thread.join(3)
        assert not cancel_thread.is_alive()
        until(lambda: len(owned.workers) == 2 and owner.calls == ["first", "second"])
        current = owned.workers[1]
        assert owner._eco_worker is current and native.native_retirement_proven(old)
        assert not native.native_retirement_proven(current)
        owner._on_eco_worker_retired(old)  # A stale exact old delivery cannot clear its replacement.
        assert owner._eco_worker is current
        with pytest.raises(RuntimeError, match="cannot restart"):
            current.start()
        owner._termination_started = True
        runtime = list(owner.runtime)
        owner._pending_chill_wake = False
        owner._resume_pending_chill_wake()
        assert owner._wake_chill_modules(auto=False) is False
        QApplication.instance().processEvents()
        assert len(owned.workers) == 2 and owner.runtime == runtime
    finally:
        release.set()
        if cancel_thread is not None:
            cancel_thread.join(3)
            assert not cancel_thread.is_alive()


@pytest.mark.parametrize("state", ["never-started", "deleted-without-proof"])
def test_unknown_or_invalid_eco_without_producer_proof_is_still_held(qt, tmp_path, state):
    owner = QMainWindow()
    worker = EcoWakeupWorker([])
    if state == "deleted-without-proof":
        worker.start()
        assert worker.wait(3000)
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
        assert not isValid(worker)
    else:
        assert not worker.isFinished() and worker.wait(0)
    now, rows, finished = [0.0], [], []
    coordinator = ShutdownRetirement(owner,
        workers=lambda: (RetainedWorker("unproved-eco", worker, True, native.poll_native_retirement),),
        cleanup=lambda: rows.append("must stay held"), finish=finished.append,
        data_root=tmp_path, timeout=1, clock=lambda: now[0],
        diagnostic_writer=lambda _root, _row: None)
    try:
        coordinator.start()
        assert not native.poll_native_retirement(worker)
        assert not finished and not rows
        now[0] = 2
        coordinator.poll()
        until(lambda: bool(finished))
        assert finished[0]["state"] == "forced-incomplete" and finished[0]["forced"]
        assert finished[0]["pending_workers"] == ["unproved-eco"] and not rows
    finally:
        coordinator._timer.stop()
        if isValid(worker):
            # Fixture owns a never-started object, not an admitted native producer.
            worker.removeEventFilter(coordinator)
            worker.deleteLater()
            QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
        owner.close()
        owner.deleteLater()


def test_restarted_qobject_cannot_consume_a_prior_generation_delete_replay(qt, tmp_path):
    owner = QMainWindow()
    now, finished, cleanup, retired = [0.0], [], [], []

    class Reusable(QThread):
        def __init__(self):
            super().__init__(owner)
            self.entered = [threading.Event(), threading.Event()]
            self.leave = [threading.Event(), threading.Event()]
            self.generation = 0

        def run(self):
            index = self.generation
            self.generation += 1
            self.entered[index].set()
            assert self.leave[index].wait(5), "Fixture must release actual Qt run"

    worker = Reusable()
    native.retain_native_retirement(worker, lambda exact: retired.append(exact))
    row = RetainedWorker("actual-restarted-worker", worker, True, native.poll_native_retirement)
    coordinator = ShutdownRetirement(owner, workers=lambda: (row,),
        cleanup=lambda: cleanup.append("must remain held"), finish=finished.append,
        data_root=tmp_path, timeout=1, clock=lambda: now[0],
        diagnostic_writer=lambda _root, _row: None)
    try:
        worker.start()
        assert worker.entered[0].wait(3)
        coordinator.start()
        coordinator._timer.stop()  # Deterministic explicit functional polls.
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
        assert isValid(worker) and id(worker) in coordinator._deferred_native_delete
        worker.leave[0].set()
        until(lambda: native.poll_native_retirement(worker))
        assert QThread.wait(worker, 0) is True and retired == [worker]
        # Post the original clone without beginning store cleanup, then model
        # a forbidden/restarted generation before Qt receives that event.
        assert coordinator._pending() == []
        assert id(worker) in coordinator._deferred_delete_posted
        worker.start()
        assert worker.entered[1].wait(3)
        assert worker.isRunning() and not QThread.wait(worker, 0)
        QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
        assert isValid(worker) and worker.isRunning()
        assert id(worker) in coordinator._deferred_native_delete
        assert coordinator._discovery_error == "DeferredDeleteGenerationChanged"
        coordinator.poll()
        assert finished == [] and cleanup == []
        worker.leave[1].set()
        assert QThread.wait(worker, 3000) is True
        now[0] = 2.0
        coordinator.poll()
        until(lambda: bool(finished))
        assert finished[0]["state"] == "forced-incomplete"
        assert finished[0]["discovery_error"] == "DeferredDeleteGenerationChanged"
        assert cleanup == [] and isValid(worker)
        assert id(worker) in coordinator._deferred_native_delete
    finally:
        for release in worker.leave:
            release.set()
        assert QThread.wait(worker, 3000) is True
        coordinator._timer.stop()
        if isValid(worker):
            worker.removeEventFilter(coordinator)
        # Unit-owned parent teardown after actual wait proof; no forced worker
        # deletion or fabricated DeferredDelete event is used by the product.
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(owner, QEvent.Type.DeferredDelete)


def test_unstarted_qthread_delete_intent_stays_held_without_native_proof(qt, tmp_path):
    owner = QMainWindow()
    worker = QThread(owner)
    now, finished, cleanup = [0.0], [], []
    coordinator = ShutdownRetirement(owner,
        workers=lambda: (RetainedWorker("unstarted-with-delete", worker, True,
                                       native.poll_native_retirement),),
        cleanup=lambda: cleanup.append("must not close"), finish=finished.append,
        data_root=tmp_path, timeout=1, clock=lambda: now[0],
        diagnostic_writer=lambda _root, _row: None)
    try:
        coordinator.start()
        coordinator._timer.stop()
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
        retained = coordinator._deferred_native_delete[id(worker)]
        assert isValid(worker) and not worker.isFinished()
        assert not native.poll_native_retirement(worker)
        worker.deleteLater()
        QCoreApplication.sendPostedEvents(worker, QEvent.Type.DeferredDelete)
        assert coordinator._deferred_native_delete[id(worker)] is retained
        now[0] = 2.0
        coordinator.poll()
        until(lambda: bool(finished))
        assert finished[0]["state"] == "forced-incomplete" and finished[0]["forced"]
        assert finished[0]["pending_workers"] == ["unstarted-with-delete"]
        assert cleanup == [] and isValid(worker)
        assert id(worker) not in coordinator._deferred_delete_posted
    finally:
        coordinator._timer.stop()
        worker.removeEventFilter(coordinator)
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(owner, QEvent.Type.DeferredDelete)
