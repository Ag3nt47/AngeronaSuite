"""Exact nonblocking native QThread retirement, separate from result/finished.

Only this functional retirement reaper may publish proof. Cosmetic animation,
thread absence, QObject deletion, result delivery and finished alone cannot.
"""
from __future__ import annotations

import weakref

from PySide6.QtCore import QCoreApplication, QObject, QThread, Qt, QTimer, Slot
from shiboken6 import isValid


_REGISTRY = None
_PROOFS = {}


def _forget_proof(identity, reference):
    if _PROOFS.get(identity) is reference:
        _PROOFS.pop(identity, None)


def native_retirement_proven(worker):
    """Prior actual native proof for this exact object, even after C++ deletion."""
    reference = _PROOFS.get(id(worker))
    return reference is not None and reference() is worker


class _NativeRetirement(QObject):
    def __init__(self, application):
        super().__init__(application)
        self._owned = {}
        self._waiting = set()
        self._delivering = set()
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._probe)

    def retain(self, worker, settled):
        if QThread.currentThread() != self.thread():
            raise RuntimeError("Native retirement admission requires the Qt owner thread")
        if worker in self._owned:
            raise RuntimeError("Native worker already has a retirement owner")
        if native_retirement_proven(worker):
            raise RuntimeError("A proven native generation cannot be reused")
        self._owned[worker] = settled
        worker.finished.connect(self._finished_candidate, Qt.ConnectionType.QueuedConnection)

    @Slot()
    def _finished_candidate(self):
        worker = self.sender()
        if worker in self._owned:
            self._waiting.add(worker)
            self._probe()

    def failed_start(self, worker):
        # Raised start is explicitly unproved. Keep custody and the native
        # finished connection; only an eventual real finished/wait proof can
        # retire it. Do not churn a timer for an unstarted/uninspectable owner.
        if worker in self._owned:
            worker.retirement_uncertain = True

    def _probe(self):
        for worker in tuple(self._waiting):
            if worker in self._delivering:
                continue
            if not isValid(worker):
                self._waiting.discard(worker)
                # Deletion without prior native proof is an unresolved hold.
                # Retain exact custody; repeated probing cannot recover it.
                continue
            try:
                finished = worker.isFinished() is True
                proven = finished and worker.wait(0) is True
            except Exception:
                proven = False
            if not proven:
                continue
            self._waiting.discard(worker)
            settled = self._owned[worker]
            self._delivering.add(worker)
            # This callback runs on Qt, after actual wait proof. It clears
            # producer references and emits its proven-retired signal before
            # registry removal/deferred QObject deletion.
            try:
                settled(worker)
            except Exception:
                # Actual native proof remains recorded. A UI delivery error
                # cannot roll it back or manufacture another producer run.
                if isValid(worker):
                    worker.deleteLater()
            finally:
                # Publish the external proof only after owner callbacks have
                # settled. A nested STOP/DeferredDelete filter must wait while
                # delivery is still reentrant, even though native wait passed.
                identity = id(worker)
                reference = weakref.ref(worker, lambda ref, key=identity: _forget_proof(key, ref))
                _PROOFS[identity] = reference
                self._delivering.discard(worker)
                self._owned.pop(worker, None)
        if self._waiting:
            if not self._timer.isActive():
                self._timer.start()
        else:
            self._timer.stop()


def retain_native_retirement(worker, settled):
    global _REGISTRY
    application = QCoreApplication.instance()
    if application is None or QThread.currentThread() != application.thread():
        raise RuntimeError("Finite GUI actions require an existing Qt owner")
    if _REGISTRY is None:
        _REGISTRY = _NativeRetirement(application)
    _REGISTRY.retain(worker, settled)


def native_start_failed(worker):
    if _REGISTRY is not None:
        _REGISTRY.failed_start(worker)


def poll_native_retirement(worker):
    """GUI-only proof/settlement hook for the existing STOP deletion filter."""
    if native_retirement_proven(worker):
        return True
    registry = _REGISTRY
    if registry is None or QThread.currentThread() != registry.thread():
        return False
    try:
        if worker not in registry._owned or worker in registry._delivering:
            return False
    except (RuntimeError, TypeError):
        return False
    if isValid(worker):
        try:
            if worker.isFinished() is True:
                registry._waiting.add(worker)
                registry._probe()
        except Exception:
            return False
    return native_retirement_proven(worker)
