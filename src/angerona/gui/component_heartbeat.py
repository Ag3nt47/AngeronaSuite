"""Bounded helper liveness presentation from copied memory publications only."""
from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
import html
import math
import time

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen, QTextCursor
from PySide6.QtWidgets import (
    QAbstractButton, QDialog, QDialogButtonBox, QLabel, QPlainTextEdit,
    QSizePolicy, QVBoxLayout,
)


EXPECTED_ROLES = ("core", "watchdog", "scanner", "blackbox")
MAX_COMPONENTS = 24
MAX_DEADLINE_SECONDS = 120.0
_LIVE_STATES = frozenset(("running", "active", "ready", "healthy", "live", "verified"))


def _update_details_text(view: QPlainTextEdit, content: str) -> None:
    """Refresh changed lines without moving the reader's viewport or selection."""
    previous = view.toPlainText()
    if content == previous:
        return
    vertical = view.verticalScrollBar()
    horizontal = view.horizontalScrollBar()
    position = (vertical.value(), horizontal.value())
    selection = view.textCursor()
    old_lines = previous.splitlines(keepends=True)
    new_lines = content.splitlines(keepends=True)
    # QTextCursor positions count UTF-16 units, including diagnostic Unicode.
    offsets = [0]
    for line in old_lines:
        offsets.append(offsets[-1] + len(line.encode("utf-16-le", "surrogatepass")) // 2)
    edits = SequenceMatcher(None, old_lines, new_lines, autojunk=False).get_opcodes()
    cursor = QTextCursor(view.document())
    cursor.beginEditBlock()
    try:
        for operation, start, end, new_start, new_end in reversed(edits):
            if operation == "equal":
                continue
            cursor.setPosition(offsets[start])
            cursor.setPosition(offsets[end], QTextCursor.KeepAnchor)
            cursor.insertText("".join(new_lines[new_start:new_end]))
    finally:
        cursor.endEditBlock()
    # The copied cursor tracks edits before the selected text. Restore it
    # before the bars, since setTextCursor may otherwise scroll it into view.
    view.setTextCursor(selection)
    vertical.setValue(position[0])
    horizontal.setValue(position[1])


def _text(value, limit: int) -> str:
    return " ".join(value.split())[:limit] if type(value) is str else ""


def _finite(value) -> float | None:
    if type(value) not in (int, float):
        return None
    try:
        result = float(value)
    except (OverflowError, ValueError):
        return None
    return result if math.isfinite(result) else None


@dataclass(frozen=True)
class ComponentHeartbeatView:
    role: str
    generation_id: str
    pid: int | None
    age_seconds: float | None
    deadline_seconds: float | None
    state: str
    reason: str
    fresh: bool


@dataclass(frozen=True)
class _HeartbeatRecord:
    role: str
    generation_id: str = ""
    pid: int | None = None
    last_heartbeat: float | None = None
    deadline: float | None = None
    state: str = "unavailable"
    reason: str = "No real heartbeat has been published."
    generation_confirmed: bool = False


class ComponentHeartbeatModel:
    """Process presence and state labels never manufacture heartbeat evidence."""

    def __init__(self) -> None:
        self._records: tuple[_HeartbeatRecord, ...] = ()
        self._history: dict[str, tuple[str, float | None, float | None]] = {}

    def publish(self, records, now: float, *, failure: str = "") -> None:
        # The provider contract is plain immutable publication copies. Reject
        # lazy iterators/custom mappings rather than invoking arbitrary accessors.
        supplied = records[:MAX_COMPONENTS] if type(records) in (tuple, list) else ()
        selected: dict[str, _HeartbeatRecord] = {}
        duplicates: set[str] = set()
        for raw in supplied:
            if type(raw) is not dict:
                continue
            role = _text(raw.get("role"), 48).lower()
            if not role:
                continue
            if role in selected:
                duplicates.add(role)
                continue
            generation = _text(raw.get("generation_id"), 192)
            heartbeat = _finite(raw.get("last_heartbeat_monotonic"))
            if heartbeat is not None and (heartbeat < 0 or heartbeat > now):
                heartbeat = None
            deadline = _finite(raw.get("deadline_seconds"))
            if deadline is not None and not 0 < deadline <= MAX_DEADLINE_SECONDS:
                deadline = None
            pid = raw.get("pid")
            pid = pid if type(pid) is int and 0 < pid <= 0xFFFFFFFF else None
            previous_generation, previous_beat, floor = self._history.get(role, ("", None, None))
            if previous_generation and generation != previous_generation:
                floor = previous_beat if floor is None else max(floor, previous_beat or floor)
            confirmed = bool(generation and heartbeat is not None and
                             (floor is None or heartbeat > floor))
            latest = previous_beat
            if heartbeat is not None:
                latest = heartbeat if latest is None else max(latest, heartbeat)
            if generation:
                self._history[role] = (generation, latest, floor)
            selected[role] = _HeartbeatRecord(
                role, generation, pid, heartbeat, deadline,
                _text(raw.get("state"), 48).lower() or "unknown",
                _text(raw.get("reason"), 512), confirmed,
            )
        for role in duplicates:
            selected[role] = _HeartbeatRecord(role, reason="Conflicting heartbeat records; liveness is unavailable.")
        roles = (EXPECTED_ROLES + tuple(role for role in selected if role not in EXPECTED_ROLES))[:MAX_COMPONENTS]
        self._records = tuple(selected.get(role) or _HeartbeatRecord(
            role, reason=_text(failure, 512) or "No real heartbeat has been published.",
        ) for role in roles)
        self._history = {role: value for role, value in self._history.items() if role in roles}

    def snapshot(self, now: float) -> tuple[ComponentHeartbeatView, ...]:
        records = self._records or tuple(_HeartbeatRecord(role) for role in EXPECTED_ROLES)
        views = []
        for record in records:
            age = None if record.last_heartbeat is None else now - record.last_heartbeat
            state, reason, fresh = record.state, record.reason, False
            if state not in _LIVE_STATES:
                reason = reason or "The component has not reported an active heartbeat state."
            elif not record.generation_id:
                state, reason = "unavailable", "The component generation is unavailable."
            elif age is None or age < 0:
                state, reason = "unavailable", "No usable real heartbeat timestamp is available."
            elif record.deadline is None:
                state, reason = "unavailable", "A finite heartbeat deadline of at most 120 seconds is required."
            elif not record.generation_confirmed:
                state, reason = "starting", "The new generation has not supplied a newer real heartbeat."
            elif age >= record.deadline:
                state, reason = "stale", "The real heartbeat exceeded its freshness deadline."
            else:
                state, fresh = "live", True
            views.append(ComponentHeartbeatView(
                record.role, record.generation_id, record.pid, age, record.deadline,
                state, reason, fresh,
            ))
        return tuple(views)


class ComponentHeartbeatStrip(QAbstractButton):
    """Small EKG lanes; polling reads only an in-memory copied publication.

    A waveform means recent liveness evidence for that exact generation. It
    does not attest sensor coverage, security health, trust or response policy.
    """

    details_requested = Signal()
    snapshot_changed = Signal()

    def __init__(self, parent=None, *, clock=time.monotonic) -> None:
        super().__init__(parent)
        self.setObjectName("ComponentHeartbeatStrip")
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.setMinimumWidth(160)
        self.setMaximumWidth(236)
        self.setFixedHeight(38)
        self._clock = clock
        self._model = ComponentHeartbeatModel()
        self._source = None
        self._details_dialog = None
        self._description = ""
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(500)
        self._poll_timer.timeout.connect(self.refresh_snapshot)
        self._animation_timer = QTimer(self)
        self._animation_timer.setInterval(50)
        self._animation_timer.timeout.connect(self._animate)
        self.clicked.connect(self.details_requested.emit)
        self.details_requested.connect(self.show_details)
        self.refresh_snapshot()

    def set_source(self, supplier) -> None:
        """Accept a nonblocking supplier of plain copied memory records only."""
        self._source = supplier if callable(supplier) else None
        self._model = ComponentHeartbeatModel()
        self.refresh_snapshot()

    def refresh_snapshot(self) -> None:
        now = self._clock()
        try:
            records = self._source() if self._source is not None else ()
            self._model.publish(records, now)
        except Exception:
            self._model.publish((), now, failure="Heartbeat publication is unavailable.")
        self._sync_presentation(now)

    def snapshot(self) -> tuple[ComponentHeartbeatView, ...]:
        return self._model.snapshot(self._clock())

    def details_text(self) -> str:
        rows = ["Component heartbeats", "",
                "Recent liveness only. A heartbeat does not verify security coverage or authorize response.",
                "Red flatline means missing, stale, disabled, starting, stopped or unavailable evidence.", ""]
        for record in self.snapshot():
            age = "unavailable" if record.age_seconds is None else f"{record.age_seconds:.1f} s"
            deadline = "unavailable" if record.deadline_seconds is None else f"{record.deadline_seconds:g} s"
            rows.extend((f"{record.role}: {record.state}", f"  PID: {record.pid or 'unavailable'}",
                         f"  Generation: {record.generation_id or 'unavailable'}",
                         f"  Real heartbeat age: {age}; deadline: {deadline}",
                         f"  Reason: {record.reason or 'Recent real heartbeat received.'}", ""))
        return "\n".join(rows)

    def _sync_presentation(self, now: float) -> None:
        records = self._model.snapshot(now)
        description = "; ".join(f"{row.role}: {row.state}" for row in records)
        if description != self._description:
            self._description = description
            self.setAccessibleName(f"Component heartbeats. {description}")
            self.setAccessibleDescription("Open heartbeat ages, exact generations and unavailable reasons. Press Enter or Space.")
            self.setToolTip(f"<p>{html.escape(description)}</p><p>Click for real heartbeat evidence. Liveness does not verify security coverage.</p>")
        if self.isVisible() and any(row.fresh for row in records):
            self._animation_timer.start()
        else:
            self._animation_timer.stop()
        self.snapshot_changed.emit()
        self.update()

    def _animate(self) -> None:
        # Freshness is evaluated again even if the supplier stops updating.
        if not any(row.fresh for row in self.snapshot()) or not self.isVisible():
            self._sync_presentation(self._clock())
            return
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.refresh_snapshot()
        self._poll_timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._poll_timer.stop()
        self._animation_timer.stop()
        super().hideEvent(event)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(220, 38)

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return QSize(160, 38)

    def keyPressEvent(self, event) -> None:  # noqa: N802
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            self.click()
            event.accept()
            return
        super().keyPressEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        now = self._clock()
        records = self._model.snapshot(now)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#101925"))
        visible = records[:4]
        cell = self.width() / max(1, len(visible))
        font = painter.font()
        font.setPointSizeF(max(6.5, min(8.0, font.pointSizeF() - 1)))
        painter.setFont(font)
        labels = {"core": "Core", "watchdog": "Watch", "scanner": "Scan", "blackbox": "BlackBox"}
        for index, record in enumerate(visible):
            left, right = index * cell + 4, (index + 1) * cell - 4
            painter.setPen(QColor("#9fb1c7"))
            label = labels.get(record.role, record.role)
            if index == 3 and len(records) > 4:
                label = f"BB +{len(records) - 4}"
            painter.drawText(QRectF(left, 0, right - left, 15), Qt.AlignCenter, label)
            painter.setPen(QPen(QColor("#28df94" if record.fresh else "#ff5363"), 1.5))
            baseline = 28.0
            path = QPainterPath(QPointF(left, baseline))
            width = max(1.0, right - left)
            phase = (now * 0.8) % 1.0
            for step in range(1, 49):
                x = step / 48
                y = 0.0
                if record.fresh:
                    position = (x + phase) % 1.0
                    for center, height, radius in ((0.40, 3, 0.06), (0.49, -11, 0.035),
                                                    (0.55, 6, 0.04), (0.69, -3, 0.09)):
                        y += height * max(0.0, 1.0 - abs(position - center) / radius)
                path.lineTo(left + x * width, baseline + y)
            painter.drawPath(path)
        if self.hasFocus():
            painter.setPen(QPen(QColor("#59baff"), 1))
            painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 3, 3)

    def show_details(self) -> None:
        if self._details_dialog is not None:
            self._details_dialog.raise_()
            self._details_dialog.activateWindow()
            return
        dialog = QDialog(self.window())
        dialog.setWindowTitle("Angerona component heartbeats")
        dialog.resize(650, 470)
        layout = QVBoxLayout(dialog)
        notice = QLabel("Real heartbeat evidence and exact generations. This view performs no process or file inspection.")
        notice.setWordWrap(True)
        layout.addWidget(notice)
        text = QPlainTextEdit()
        text.setObjectName("ComponentHeartbeatDetailsText")
        text.setReadOnly(True)
        text.setUndoRedoEnabled(False)
        text.setPlainText(self.details_text())
        layout.addWidget(text, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        update = lambda: _update_details_text(text, self.details_text())
        self.snapshot_changed.connect(update)

        def finished(_result) -> None:
            self.snapshot_changed.disconnect(update)
            self._details_dialog = None
            dialog.deleteLater()

        dialog.finished.connect(finished)
        self._details_dialog = dialog
        dialog.show()
