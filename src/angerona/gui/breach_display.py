"""Presentation of a first-party breach projection and external review reports."""
from __future__ import annotations

import json
import html
import weakref
from dataclasses import asdict

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QGridLayout, QLabel, QPlainTextEdit, QPushButton,
    QApplication, QMessageBox, QVBoxLayout, QWidget,
)
from shiboken6 import isValid

from angerona.core.breach_state import BreachActionAvailability, BreachDisplaySnapshot
from angerona.gui.header_controls import motion_allowed


class BreachOutline(QWidget):
    """Cheap client-edge outline; it never intercepts pointer or focus input."""

    def __init__(self, parent):
        super().__init__(parent)
        self._color = QColor("#ef4444")
        self.setObjectName("ConfirmedBreachOutline")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        parent.installEventFilter(self)
        self.hide()

    def set_color(self, color):
        self._color = QColor(color)
        self.setGeometry(self.parentWidget().rect())
        self.show()
        self.raise_()
        self.update()

    def eventFilter(self, watched, event):  # noqa: N802
        if watched is self.parentWidget() and event.type() == QEvent.Type.Resize:
            self.setGeometry(watched.rect())
        return False

    def paintEvent(self, _event):  # noqa: N802
        painter = QPainter(self)
        painter.setPen(QPen(self._color, 3))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(self.rect().adjusted(1, 1, -2, -2))
        painter.end()


class AfterActionReportDialog(QDialog):
    """Literal evidence/provenance view; availability comes from a typed router."""

    action_requested = Signal(str)

    def __init__(self, report, parent=None, *, confirmed=False, availability=()):
        super().__init__(parent)
        self.setWindowTitle("Angerona — After-action report")
        self.resize(860, 650)
        self.setMinimumSize(520, 380)
        self._report = report
        self._confirmed = bool(confirmed)
        self._view = "investigate"
        layout = QVBoxLayout(self)
        self.notice = QLabel(self._case_notice(report) if confirmed
                             else "External scanner evidence — review findings and coverage before taking action.")
        self.notice.setTextFormat(Qt.TextFormat.PlainText)
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setUndoRedoEnabled(False)
        self.text.document().setMaximumBlockCount(4000)
        layout.addWidget(self.text, 1)
        self.actions = {}
        buttons = QGridLayout()
        grants = {getattr(item, "action", ""): item for item in availability}
        for index, (action, label) in enumerate((
            ("investigate", "Investigate"), ("trace", "Trace"), ("isolate", "Isolate"),
            ("patch", "Patch"), ("kill", "Kill"), ("lift_lockdown", "Lift Lockdown"),
            ("review_resolved", "Mark reviewed / resolved"),
        )):
            button = QPushButton(label)
            self.actions[action] = button
            local_review = action in {"investigate", "trace"}
            grant = grants.get(action)
            button.setEnabled(local_review or bool(confirmed and getattr(grant, "enabled", False)))
            if not local_review:
                button.setToolTip(getattr(grant, "reason", "") or
                                  "A validated target and authorized installed response adapter are required.")
            if action == "investigate":
                button.clicked.connect(self.show_investigation)
            elif action == "trace":
                button.clicked.connect(self.show_trace)
            else:
                button.clicked.connect(lambda _checked=False, selected=action: self.action_requested.emit(selected))
            buttons.addWidget(button, index // 3, index % 3)
        layout.addLayout(buttons)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        layout.addWidget(close)
        self.show_investigation()
        self.outline = BreachOutline(self)
        if confirmed:
            self.outline.set_color("#ef4444")

    def _display(self, data):
        try:
            rendered = json.dumps(data, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            rendered = "The report has unsupported data; use its preserved original for review."
        self.text.setPlainText(rendered.replace("\x00", "")[:96000])

    @staticmethod
    def _case_notice(report):
        report = report if type(report) is dict else {}
        case = str(report.get("case_id", "unavailable"))[:160]
        state = str(report.get("containment_state", "unknown"))[:160]
        return f"Confirmed breach · case {case} · containment: {state}"

    def show_investigation(self):
        self._view = "investigate"
        self._display(self._report)

    def show_trace(self):
        self._view = "trace"
        report = self._report if type(self._report) is dict else {}
        selected = {key: report[key] for key in (
            "case_id", "request_id", "tool", "version", "commit", "sha256", "report",
            "provenance", "coverage", "references", "details",
        ) if key in report}
        self._display(dict(review="Evidence and provenance trace; this does not contact a remote target.",
                           trace=selected))

    def update_report(self, report, availability=(), *, confirmed=False):
        from angerona.gui.component_heartbeat import _update_details_text
        position = self.text.verticalScrollBar().value()
        selection = self.text.textCursor()
        self._report = report
        self._confirmed = bool(confirmed)
        self.notice.setText(self._case_notice(report)
                            if confirmed else "Retained review record — current state: " + str(report.get("state", "unknown"))[:80])
        previous = self.text.toPlainText()
        view = self._view
        # Render into a temporary plain string, then update the retained
        # document rather than resetting the reader's scroll and selection.
        if view == "trace":
            selected = {key: report[key] for key in ("case_id", "request_id", "tool", "version", "commit", "sha256", "report",
                                                      "provenance", "coverage", "references", "details") if key in report}
            data = dict(review="Evidence and provenance trace; this does not contact a remote target.", trace=selected)
        else:
            data = report
        rendered = json.dumps(data, indent=2, ensure_ascii=False).replace("\x00", "")[:96000]
        if rendered != previous:
            _update_details_text(self.text, rendered)
            self.text.setTextCursor(selection)
            self.text.verticalScrollBar().setValue(position)
        grants = {item.action: item for item in availability if type(item) is BreachActionAvailability}
        for action, button in self.actions.items():
            if action in {"investigate", "trace"}:
                continue
            grant = grants.get(action)
            button.setEnabled(bool(confirmed and grant is not None and grant.enabled))
            button.setToolTip(grant.reason if grant else "A validated target and authorized installed response adapter are required.")


def _valid_projection(snapshot):
    if (type(snapshot) is not BreachDisplaySnapshot or type(snapshot.active) is not bool
            or type(snapshot.sequence) is not int or not 0 <= snapshot.sequence <= 2**63 - 1):
        return False
    for name, bound in (("state", 80), ("summary", 4096), ("case_id", 160), ("containment_state", 160)):
        value = getattr(snapshot, name)
        if type(value) is not str or len(value) > bound or "\x00" in value:
            return False
    if snapshot.active and not snapshot.case_id:
        return False
    if type(snapshot.details) is not tuple or len(snapshot.details) > 64:
        return False
    if any(type(row) is not tuple or len(row) != 2 or any(type(value) is not str or len(value) > 4096 for value in row)
           for row in snapshot.details):
        return False
    if type(snapshot.actions) is not tuple or len(snapshot.actions) > 16:
        return False
    return all(type(item) is BreachActionAvailability and type(item.action) is str and type(item.enabled) is bool
               and type(item.confirmation_required) is bool and type(item.reason) is str and len(item.reason) <= 2000
               and item.action in {"investigate", "trace", "isolate", "patch", "kill", "lift_lockdown", "review_resolved"}
               for item in snapshot.actions)


class BreachDisplayBridge(QObject):
    """Memory-only projection; it accepts no external report dictionaries."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.snapshot = None
        self._outlines = weakref.WeakKeyDictionary()
        self._orange = False
        self._last_alert_case = ""
        self._closed = False
        self._label_signature = None
        self._needs_restore = False
        self.dialog = None
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(500)
        self.poll_timer.timeout.connect(self.poll)
        self.flash_timer = QTimer(self)
        self.flash_timer.setInterval(1000)
        self.flash_timer.timeout.connect(self._flash)

    @property
    def active(self):
        return self.snapshot is not None and self.snapshot.active

    def poll(self):
        if self._closed:
            return
        controller = getattr(self.window.manager, "_breach_state_controller", None)
        if controller is not None:
            try:
                self.apply(controller.snapshot())
            except Exception:
                # Collector loss cannot silently clear an existing breach.
                pass
        self._sync_visibility()

    def apply(self, snapshot):
        if self._closed or not _valid_projection(snapshot):
            return False
        previous = self.snapshot
        if previous is not None and snapshot.sequence < previous.sequence:
            return False
        changed = previous != snapshot
        self.snapshot = snapshot
        if not changed:
            self._sync_visibility()
            return True
        self._sync_summary_views(snapshot)
        if self.active:
            if changed:
                self._orange = False
            self._paint_warning()
            if self._last_alert_case != snapshot.case_id:
                self._last_alert_case = snapshot.case_id
                if bool(getattr(self.window.config, "breach_alert_popup_enabled", True)):
                    self.open_report()
            elif changed and self.dialog is not None and isValid(self.dialog):
                self.dialog.update_report(self._report(), self._available_actions(), confirmed=True)
        else:
            self.flash_timer.stop()
            for outline in tuple(self._outlines.values()):
                if isValid(outline):
                    outline.hide()
            self._needs_restore = True
            if self.window.isVisible():
                self.restore_posture()
            if changed and self.dialog is not None and isValid(self.dialog):
                self.dialog.update_report(self._report(), (), confirmed=False)
        self._sync_visibility()
        return True

    def _sync_summary_views(self, snapshot):
        cards = getattr(self.window, "cards", None)
        if callable(getattr(cards, "set_breach_override", None)):
            cards.set_breach_override(snapshot, open_report=self.open_report)
        footer = getattr(self.window, "_dashboard_footer", None)
        if callable(getattr(footer, "set_breach_override", None)):
            footer.set_breach_override(snapshot)
        if not snapshot.active:
            reader = getattr(self.window, "_posture_reader", None)
            if callable(getattr(reader, "request", None)):
                reader.request()

    def _owned_windows(self):
        owned = [self.window]
        app = QApplication.instance()
        if app is not None:
            for candidate in app.topLevelWidgets()[:64]:
                if candidate is not self.window and isinstance(candidate, QDialog) and self.window.isAncestorOf(candidate):
                    owned.append(candidate)
        return owned

    def _sync_visibility(self):
        if self._closed:
            return
        visible = any(widget.isVisible() for widget in self._owned_windows())
        attached = getattr(self.window.manager, "_breach_state_controller", None) is not None
        if visible or attached:
            if not self.poll_timer.isActive():
                self.poll_timer.start()
        else:
            self.poll_timer.stop()
        if visible:
            if self.active:
                self._paint_warning()
            elif self._needs_restore and self.window.isVisible():
                self.restore_posture()
        animate = self.active and visible and motion_allowed(getattr(self.window, "config", None))
        if animate:
            if not self.flash_timer.isActive():
                self.flash_timer.start()
        else:
            self.flash_timer.stop()
            if self.active:
                self._orange = False
                self._paint_warning()

    def _paint_warning(self):
        windows = [window for window in self._owned_windows() if window.isVisible()]
        if not windows:
            return
        color = "#fb923c" if self._orange else "#ef4444"
        label = self.window.posture_lbl
        signature = (color, self.snapshot.summary, self.snapshot.containment_state)
        if self.window.isVisible() and signature != self._label_signature:
            self._label_signature = signature
            label.setText("⚠️Breached⚠️")
            label.setAccessibleName("Confirmed breach. Open after-action report.")
            label.setStyleSheet(f"color:{color};font-weight:900;font-size:12px;letter-spacing:1px;")
            label.setToolTip("<qt>Confirmed breach — " + html.escape(self.snapshot.summary)
                             + "<br>Containment: " + html.escape(self.snapshot.containment_state) + "</qt>")
        for window in windows:
            outline = self._outlines.get(window)
            if outline is None or not isValid(outline):
                existing = getattr(window, "outline", None)
                outline = existing if isinstance(existing, BreachOutline) else BreachOutline(window)
                self._outlines[window] = outline
            if outline._color.name() != color or not outline.isVisible() or outline.geometry() != window.rect():
                outline.set_color(color)

    def _flash(self):
        if self._closed:
            return
        if not self.active or not motion_allowed(getattr(self.window, "config", None)):
            self._sync_visibility()
            return
        self._orange = not self._orange
        self._paint_warning()

    def restore_posture(self):
        self._label_signature = None
        self._needs_restore = False
        posture = getattr(self.window, "_last_posture", None)
        label = self.window.posture_lbl
        if type(posture) is dict and all(name in posture for name in ("score", "label", "color")):
            label.setText(f"POSTURE {posture['score']} · {posture['label']}")
            label.setStyleSheet(f"color:{posture['color']}; font-weight:800; font-size:11px; letter-spacing:1px;")
            label.setToolTip(getattr(self.window, "_last_posture_tooltip", "Composite security posture (0–100)."))
        else:
            label.setText("POSTURE —")
            label.setStyleSheet("")
        label.setAccessibleName("Security posture")

    def _report(self):
        return dict(asdict(self.snapshot), provenance="Angerona verified breach controller") if self.snapshot is not None else {}

    def _available_actions(self):
        controller = getattr(self.window.manager, "_breach_state_controller", None)
        if not callable(getattr(controller, "request_action", None)):
            return ()
        return self.snapshot.actions

    def open_report(self):
        if self._closed or self.snapshot is None:
            return None
        if self.dialog is None or not isValid(self.dialog):
            self.dialog = AfterActionReportDialog(self._report(), self.window, confirmed=self.active,
                                                  availability=self._available_actions())
            self.dialog.action_requested.connect(self._request_action)
        else:
            self.dialog.update_report(self._report(), self._available_actions(), confirmed=self.active)
        self.dialog.show()
        self.dialog.raise_()
        return self.dialog

    def _request_action(self, action):
        if self._closed:
            return
        snapshot = self.snapshot
        grant = next((item for item in self._available_actions() if item.action == action and item.enabled), None)
        if snapshot is None or grant is None:
            return
        if grant.confirmation_required and QMessageBox.question(
                self.dialog or self.window, "Confirm breach response",
                f"Request {action.replace('_', ' ')} for case {snapshot.case_id}?\n{grant.reason}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        controller = getattr(self.window.manager, "_breach_state_controller", None)
        if controller is not None:
            try:
                current = controller.snapshot()
            except Exception:
                current = None
            available = next((item for item in current.actions if item.action == action and item.enabled), None) if _valid_projection(current) else None
            if not _valid_projection(current) or current.case_id != snapshot.case_id or available is None:
                if self.dialog is not None:
                    self.dialog.notice.setText("Response availability changed; review the current case before retrying.")
                return
            try:
                queued = controller.request_action(snapshot.case_id, action)
            except Exception:
                if self.dialog is not None:
                    self.dialog.notice.setText("Response request outcome is unavailable; review the case journal.")
                return
            if self.dialog is not None:
                self.dialog.notice.setText("Response request queued; its verified outcome will appear in this case."
                                           if queued else "Response was not queued; review the current case and response status.")

    def shutdown(self):
        self._closed = True
        self.poll_timer.stop()
        self.flash_timer.stop()
        if self.dialog is not None and isValid(self.dialog):
            self.dialog.close()
