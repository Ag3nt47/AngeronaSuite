"""Bounded Qt presentation recovery; no engine or security-policy authority."""
from __future__ import annotations

from collections import deque
import json
import math
import time
import weakref

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout
from shiboken6 import isValid


def _write_record(record: dict) -> None:
    # Reuse the Core's private, nonblocking-admission, bounded normal logger.
    # Its existing capacity holds preserve evidence; this adds no file or key.
    try:
        from angerona.core.crashlog import _write
        _write("DISPLAY_RECOVERY", json.dumps(record, sort_keys=True))
    except Exception:
        pass  # A diagnostic failure must not prevent a presentation retry.


class DisplayRecovery(QObject):
    """Try a normal Qt restore, then one plain restore, for one live owner.

    A delivered central-widget paint and coherent Qt state are advisory display
    evidence. They do not prove readable pixels, compositor health, protection,
    sensor coverage or completion of any operation.
    """

    ATTEMPT_MS = 900

    def __init__(self, owner, *, normal, plain, failed, terminating, record=None):
        super().__init__(owner)
        self._owner = weakref.ref(owner)
        self._normal = normal
        self._plain = plain
        self._failed = failed
        self._terminating = terminating
        self._record_sink = record or _write_record
        self.records = deque(maxlen=16)
        self._active = False
        self._attempt = 0
        self._epoch = 0
        self._paint_seen = False
        self._last_clock = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        owner.installEventFilter(self)
        self._central = owner.centralWidget()
        if self._central is not None:
            self._central.installEventFilter(self)

    def _live(self):
        owner = self._owner()
        return owner if (owner is not None and isValid(owner) and not self._terminating()) else None

    def _record(self, phase, outcome, error=None):
        row = {"schema": 1, "phase": phase, "outcome": outcome,
               "attempt": self._attempt, "error_type": type(error).__name__[:64] if error else ""}
        self.records.append(row)
        try:
            self._record_sink(dict(row))
        except Exception:
            pass

    def decoration_failed(self, error):
        self._record("plain", "decoration-unavailable", error)

    def _clock(self):
        try:
            value = float(time.monotonic())
            if not math.isfinite(value) or (self._last_clock is not None and value < self._last_clock):
                raise ValueError("Unavailable display clock")
            self._last_clock = value
            return value
        except Exception as error:
            self._record("clock", "unavailable", error)
            return None

    def request(self):
        if self._live() is None:
            return False
        self._timer.stop()
        self._epoch += 1
        self._active = True
        self._attempt = 0
        self._begin_attempt()
        return True

    def cancel(self):
        was_active = self._active
        self._active = False
        self._epoch += 1
        self._timer.stop()
        if was_active:
            self._record("cancel", "cancelled")

    def eventFilter(self, watched, event):  # noqa: N802 - Qt signature
        if self._active:
            if watched is self._owner() and event.type() == QEvent.Hide:
                self.cancel()  # An operator hide must not be undone by a retry.
            elif watched is self._central and event.type() == QEvent.Paint:
                self._paint_seen = True
                # The check runs after Qt returns from the paint event.
                self._timer.start(0)
        return False

    def _begin_attempt(self):
        owner = self._live()
        if not self._active or owner is None:
            self.cancel()
            return
        self._attempt += 1
        self._paint_seen = False
        self._clock()  # Optional diagnostics; this clock never extends a retry.
        self._timer.stop()
        self._timer.deleteLater()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        epoch, attempt = self._epoch, self._attempt
        self._timer.timeout.connect(lambda: self._verify(epoch, attempt))
        phase = "normal" if self._attempt == 1 else "plain"
        self._record(phase, "requested")
        restore_failed = False
        try:
            (self._normal if self._attempt == 1 else self._plain)()
            if self._central is not None and isValid(self._central):
                self._central.update()
        except Exception as error:
            self._record(phase, "failed", error)
            restore_failed = True
        if self._active:
            self._timer.start(0 if restore_failed else self.ATTEMPT_MS)

    def _coherent(self, owner):
        central = self._central
        return bool(
            central is not None and isValid(central)
            and owner.isVisible() and not owner.isMinimized() and owner.updatesEnabled()
            and central.isVisible() and central.updatesEnabled()
            and not central.contentsRect().isEmpty()
        )

    def _verify(self, epoch, attempt):
        if epoch != self._epoch or attempt != self._attempt:
            return  # A retired request/attempt cannot consume its successor.
        owner = self._live()
        if not self._active or owner is None:
            self.cancel()
            return
        phase = "normal" if self._attempt == 1 else "plain"
        self._clock()
        try:
            confirmed = self._paint_seen and self._coherent(owner)
        except RuntimeError:
            confirmed = False
        if confirmed:
            self._active = False
            self._record(phase, "paint-observed")
            return
        if self._attempt == 1:
            self._begin_attempt()
            return
        self._active = False
        self._record("notice", "failed")
        self._failed(tuple(dict(row) for row in self.records))


class DisplayRecoveryNotice(QDialog):
    """Plain, nonmodal recovery choices with ordinary STOP ownership."""

    def __init__(self, owner, *, retry, stop):
        super().__init__(owner)
        self.setWindowTitle("Angerona — Display recovery")
        self.setWindowModality(Qt.NonModal)
        self.setAttribute(Qt.WA_DeleteOnClose, False)
        self.setProperty("_angerona_no_reveal", True)
        self.setProperty("_angerona_orb_ignore", True)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        layout = QVBoxLayout(self)
        message = QLabel(
            "The dashboard did not confirm a Qt paint after two display attempts. "
            "This is a presentation issue; protection and sensor coverage are not verified by this notice. "
            "Retry display makes two bounded presentation attempts. Safe STOP uses Angerona's normal shutdown. "
            "After it exits, use the normal Safe Startup launcher if recovery is still needed."
        )
        message.setWordWrap(True)
        message.setTextFormat(Qt.PlainText)
        layout.addWidget(message)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        layout.addWidget(self.details)
        buttons = QHBoxLayout()
        retry_button = QPushButton("Retry display")
        retry_button.clicked.connect(lambda: (self.hide(), retry()))
        stop_button = QPushButton("Safe STOP")
        stop_button.clicked.connect(stop)
        close_button = QPushButton("Close notice")
        close_button.clicked.connect(self.close)
        for button in (retry_button, stop_button, close_button):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.resize(680, 360)

    def show_records(self, records):
        self.details.setPlainText(json.dumps(list(records)[-16:], indent=2))
        self.showNormal()
        self.raise_()
        self.activateWindow()
