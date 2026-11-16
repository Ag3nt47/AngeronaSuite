"""Read-only ordinary-source family retirement for standalone presenters.

This observer may retire only its own application. It never writes a STOP,
looks up generic installed control, selects another PID or changes policy.
"""
from __future__ import annotations

import math
import os
import threading
from pathlib import Path

from angerona.resilience.source_stop import SOURCE_SESSION_ENV, join_source_session


class SourceSidecarAdmissionError(RuntimeError):
    """An explicit source-family reference could not be admitted."""


def _retirement_reason(context) -> str:
    if context.is_stop_requested() is True:
        return "source-stop"
    superseded = getattr(context, "is_superseded", None)
    if callable(superseded) and superseded() is True:
        return "source-superseded"
    return ""


class SourceSidecarStop:
    """One admitted epoch, one read-only worker, and a cached Qt exit event."""

    def __init__(self, context, *, interval: float = 0.25):
        if (type(interval) not in (int, float) or not math.isfinite(interval)
                or not 0.01 <= interval <= 2.0):
            raise ValueError("Source sidecar observation interval is invalid")
        self._context, self._interval = context, float(interval)
        self._stop = threading.Event()
        self._exit = threading.Event()
        self._done = threading.Event()
        self._thread = None
        self._start_attempted = False
        self.reason = ""
        self.error_type = ""

    def _observe_once(self):
        try:
            reason = _retirement_reason(self._context)
        except Exception as error:
            self.error_type = type(error).__name__
            return
        self.error_type = ""
        if reason:
            self.reason = reason
            self._exit.set()

    def start(self):
        if self._start_attempted:
            return
        self._start_attempted = True
        if self._stop.is_set() or self._exit.is_set():
            self._done.set()
            return
        self._thread = threading.Thread(target=self._run, name="SourceSidecarStop", daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self._stop.set()  # A late bootstrap must perform no observations.
            raise

    def _run(self):
        try:
            while not self._stop.is_set() and not self._exit.is_set():
                self._observe_once()
                if self._exit.is_set() or self._stop.wait(self._interval):
                    break
        finally:
            self._done.set()

    def exit_requested(self) -> bool:
        """Memory-only: safe for the Qt timer; never performs source/native I/O."""
        return self._exit.is_set()

    def request_stop(self):
        """Cancel observation only, without manufacturing family exit intent."""
        self._stop.set()

    def stop(self, *, timeout: float = 2.0) -> bool:
        """Join after the Qt loop ends; a timeout never reports retirement."""
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 <= timeout <= 2.0):
            raise ValueError("Source sidecar retirement deadline is invalid")
        self.request_stop()
        thread = self._thread
        if thread is None:
            return not self._start_attempted or self._done.is_set()
        if thread is threading.current_thread() or thread.ident is None:
            return False
        thread.join(timeout=timeout)
        return self._done.is_set() and not thread.is_alive()


def admit_source_sidecar(storage: Path) -> SourceSidecarStop | None:
    """Capture once; a no-reference history viewer may remain independent.

    An explicitly inherited stopped/superseded epoch always retires. A manual
    viewer with no reference may review history after that family stopped; it
    does not follow a future epoch or become a member of a protected install.
    """
    reference = os.environ.get(SOURCE_SESSION_ENV)
    context = join_source_session(Path(storage), epoch=reference, role="peer")
    if context is None:
        if reference is not None:
            raise SourceSidecarAdmissionError("Source sidecar session admission is held")
        return None  # Installed/elevated/manual diagnostics use no source domain.
    observer = SourceSidecarStop(context)
    observer._observe_once()  # Startup only: QApplication does not exist yet.
    if reference is None and observer.exit_requested():
        return None
    if not observer.exit_requested() and context.respawn_allowed() is not True:
        raise SourceSidecarAdmissionError("Source sidecar session admission is held")
    # Publish only this already-admitted process's family reference, so the
    # native PID/birth/image/argv adoption probe can match its actual epoch.
    # The environment never grants admission or installs STOP authority.
    os.environ[SOURCE_SESSION_ENV] = context.epoch
    return observer


def install_qt_stop(app, observer: SourceSidecarStop):
    """Read cached intent on Qt and quit only this presenter application."""
    from PySide6.QtCore import QTimer

    timer = QTimer(app)
    timer.setInterval(100)

    def check_cached_intent():
        if observer.exit_requested():
            timer.stop()
            app.quit()

    timer.timeout.connect(check_cached_intent)
    app.aboutToQuit.connect(observer.request_stop)
    timer.start()
    return timer
