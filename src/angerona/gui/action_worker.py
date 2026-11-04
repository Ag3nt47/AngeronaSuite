"""Bounded retained ownership for finite GUI-requested background producers."""
from __future__ import annotations

from PySide6.QtCore import QThread, Qt, Signal
from shiboken6 import isValid
from angerona.gui.native_retirement import native_retirement_proven, native_start_failed, poll_native_retirement, retain_native_retirement


_ACTIVE = set()
_CLOSING = False
_LIMIT = 8


class FiniteActionWorker(QThread):
    piece = Signal(str)
    retired = Signal()

    def __init__(self, function, name):
        super().__init__()  # Never destroyed with a dialog's QObject parent.
        self.setObjectName(name)
        self._function = function
        self.outcome = (None, "Producer did not return a verified result.")
        self.admission_error = ""
        self.retirement_uncertain = False
        self._start_attempted = False

    def start(self, *args, **kwargs):
        if self._start_attempted:
            raise RuntimeError("A finite action native generation cannot restart")
        self._start_attempted = True
        return super().start(*args, **kwargs)

    def run(self):
        try:
            if self.isInterruptionRequested():
                raise RuntimeError("Action cancelled before producer admission")
            result = self._function(self)
        except Exception as error:
            self.outcome = (None, (type(error).__name__ + ": " + str(error))[:1600])
        else:
            self.outcome = (result, "")
        finally:
            self._function = None


def _retired(worker):
    try:
        worker.retirement_uncertain = False
        worker.retired.emit()  # Qt owner thread, after actual wait(0) proof.
    finally:
        _ACTIVE.discard(worker)
        worker.deleteLater()


def start_finite_action(function, *, name, finished, piece=None):
    """Admit on Qt; only native finished reaches the owner's terminal slot."""
    if _CLOSING or len(_ACTIVE) >= _LIMIT:
        return None
    worker = FiniteActionWorker(function, name)
    _ACTIVE.add(worker)
    try:
        retain_native_retirement(worker, _retired)
        worker.retired.connect(finished, Qt.ConnectionType.DirectConnection)
        if piece is not None:
            worker.piece.connect(piece, Qt.ConnectionType.QueuedConnection)
        worker.start()
    except BaseException as error:
        worker.admission_error = type(error).__name__
        worker.retirement_uncertain = True
        worker.outcome = (None, "Action launch failed; native retirement remains unproved (" + worker.admission_error + ").")
        worker.requestInterruption()
        native_start_failed(worker)
        # Keep even an apparently unstarted raised admission: wait(0) alone
        # is not an authenticated never-started proof in the STOP contract.
    return worker


def active_finite_actions():
    """Exact retained native workers for the suite's STOP retirement barrier."""
    return tuple(_ACTIVE)


def finite_action_retirement_proven(worker):
    return native_retirement_proven(worker)


def poll_finite_action_retirement(worker):
    return poll_native_retirement(worker)


def hold_finite_actions():
    """Stop later admission and request cancellation; this does not prove exit."""
    global _CLOSING
    _CLOSING = True
    for worker in tuple(_ACTIVE):
        if isValid(worker):
            worker.requestInterruption()
