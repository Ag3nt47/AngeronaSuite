"""Nonblocking, application-shared admission for CVE row analysis only.

Two detail analyses may run at once. There is no waiting queue. A result
or interruption request never releases a running worker's reservation.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import QObject, QThread, QTimer
from PySide6.QtWidgets import QApplication


DETAIL_WORKER_LIMIT = 2
_RETIRE_RETRY_MS = 100


@dataclass
class _Reservation:
    worker: QThread | None = None
    retired: Callable[[], None] | None = None


class DetailAnalysisAdmission(QObject):
    """Own reservations through the exact worker's Qt completion state.

    Qt completion does not prove that an OS thread finished all TLS cleanup.
    """

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._reservations: dict[object, _Reservation] = {}
        self._retiring: set[object] = set()
        self._closing = False
        self._retry = QTimer(self)
        self._retry.setSingleShot(True)
        self._retry.setInterval(_RETIRE_RETRY_MS)
        self._retry.timeout.connect(self._retry_retiring)

    def _require_gui_thread(self) -> None:
        if QThread.currentThread() != self.thread():
            raise RuntimeError("CVE detail admission requires its Qt owner thread")

    @property
    def active_count(self) -> int:
        self._require_gui_thread()
        return len(self._reservations)

    @property
    def closing(self) -> bool:
        self._require_gui_thread()
        return self._closing

    def reserve(self) -> object | None:
        self._require_gui_thread()
        if self._closing or len(self._reservations) >= DETAIL_WORKER_LIMIT:
            return None
        token = object()
        self._reservations[token] = _Reservation()
        return token

    def attach(
        self, token: object, worker: QThread, retired: Callable[[], None]
    ) -> None:
        self._require_gui_thread()
        reservation = self._reservations[token]
        if reservation.worker is not None:
            raise RuntimeError("CVE detail reservation is already attached")
        reservation.worker = worker
        reservation.retired = retired
        # Dialog-parent destruction can discard its finished signal before the
        # GUI receives it. The application-owned coordinator must also be this
        # QThread's QObject parent, not only its last Python reference.
        worker.setParent(self)
        worker.finished.connect(lambda: self._retire(token, worker))

    def abandon(self, token: object) -> None:
        """Undo failed startup, retaining any worker that actually started."""
        self._require_gui_thread()
        reservation = self._reservations.get(token)
        if reservation is None:
            return
        worker = reservation.worker
        if worker is not None:
            try:
                worker.requestInterruption()
            except RuntimeError:
                pass
        self._retire(token, worker)

    def _retire(self, token: object, worker: QThread | None) -> None:
        self._require_gui_thread()
        reservation = self._reservations.get(token)
        if reservation is None or reservation.worker is not worker:
            return
        if worker is not None:
            try:
                running = worker.isRunning()
            except RuntimeError:
                running = False  # Qt has already deleted this exact worker.
            if running:
                self._retiring.add(token)
                if not self._retry.isActive():
                    self._retry.start()
                return
        self._reservations.pop(token)
        self._retiring.discard(token)
        if not self._retiring:
            self._retry.stop()
        if reservation.retired is not None:
            reservation.retired()

    def _retry_retiring(self) -> None:
        for token in tuple(self._retiring):
            reservation = self._reservations.get(token)
            if reservation is not None:
                self._retire(token, reservation.worker)

    def shutdown(self) -> None:
        """Refuse new work; request cancellation without releasing live owners."""
        self._require_gui_thread()
        self._closing = True
        for token in tuple(self._reservations):
            self.abandon(token)


def detail_analysis_admission() -> DetailAnalysisAdmission:
    app = QApplication.instance()
    if app is None or QThread.currentThread() != app.thread():
        raise RuntimeError("CVE detail admission requires the QApplication thread")
    admission = getattr(app, "_angerona_cve_detail_admission", None)
    if admission is None:
        admission = DetailAnalysisAdmission(app)
        app._angerona_cve_detail_admission = admission
        app.aboutToQuit.connect(admission.shutdown)
    return admission
