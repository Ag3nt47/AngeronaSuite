"""Shared, asynchronous presentation of maintained third-party scanner adapters."""
from __future__ import annotations

import copy
import contextlib
import importlib
import html
import json
import math
from pathlib import Path
import queue
import threading
import time
import uuid
from urllib.parse import urlsplit

from PySide6.QtCore import QEvent, QObject, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QActionGroup, QDesktopServices, QPainter, QTextCursor, QTextOption
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox, QTabWidget, QToolButton,
    QHeaderView, QSizePolicy, QStyle, QStyleOptionToolButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)
from shiboken6 import isValid

from angerona.core.config import (
    SCANNER_REPORT_COUNT_MAX,
    SCANNER_REPORT_COUNT_UNLIMITED,
    scanner_report_count,
    valid_scanner_report_count,
)
from angerona.gui.presentation_timer import PresentationTimer
from angerona.gui.progress_ring import ProgressRing
from angerona.gui.theme import set_function_role

_PROJECT = "https://github.com/interplains/Zero-Breach-Toolkit"
_RELEASE = _PROJECT + "/releases/tag/v0.1.10"
_COMMUNITY_SETTINGS = {
    "community_rules_enabled": ("Use individually activated community YARA rules", False),
    "community_playbooks_enabled": ("Use individually activated community SOAR playbooks", False),
}
_SETTINGS = {
    "github_tools_enabled": ("Enable curated scanners", True),
    "github_tools_auto_prepare": ("Prepare the pinned scanner after dashboard startup", True),
    "github_tools_allow_download": ("Allow verified downloads for missing scanner files", True),
    "spyware_scan_native_enabled": ("Include native SpywareGuard in Spyware Scan", True),
    "spyware_scan_zero_breach_enabled": ("Include Zero-Breach in Spyware Scan", True),
    "spyware_scan_verify_admin": ("Verify current privilege coverage before Spyware Scan", True),
    "breach_auto_isolate_enabled": ("Automatically request network lockdown for confirmed breaches", True),
    **_COMMUNITY_SETTINGS,
}
_REPORT_REVIEW_PAGE_SIZE = 32
_LIMITS = {
    "github_tools_job_limit_mib": ("Working data per job (MiB)", 256, 64, 1024),
    "github_tools_report_limit_mib": ("Retained reports (MiB)", 64, 8, 256),
    "github_tools_timeout_seconds": ("Standalone toolkit deadline (seconds)", 300, 30, 900),
    "spyware_scan_timeout_seconds": ("Spyware Scan default budget (seconds)", 3600, 30, 14400),
    "spyware_scan_cpu_percent": ("Scanner CPU ceiling (%)", 70, 10, 90),
    "spyware_scan_memory_mib": ("Scanner memory ceiling (MiB)", 512, 128, 2048),
    "spyware_scan_background_percent": ("Routine background pace during scan (%)", 10, 5, 50),
}


def _extra_report_choice(snapshot):
    """Copied review facts only; backend repeats every admission guard."""
    storage = snapshot.get("storage")
    if (snapshot.get("next_report_count_limit") is not None
            or snapshot.get("storage_review_error") or type(storage) is not dict
            or storage.get("unknown_entries") is not False or storage.get("inventory_gap")):
        return None
    count, limit = storage.get("retained_reports"), storage.get("report_limit")
    if (type(count) is not int or type(limit) is not int
            or not 1 <= limit <= count < SCANNER_REPORT_COUNT_MAX
            or storage.get("finite_report_limit") != SCANNER_REPORT_COUNT_MAX
            or storage.get("omitted_reports", 0) != 0):
        return None
    return count, count + 1


def _backend():
    return importlib.import_module("angerona.core.curated_tools")


class _ScanLabel(QLabel):
    """Wrap copied text without making a path the page's minimum width."""

    def setText(self, text):  # noqa: N802
        if self.text() == text:
            return
        super().setText(text)
        # Preserve exact selectable text; tooltip markup cannot interpret input.
        self.setToolTip("<qt>" + html.escape(text).replace("\n", "<br>") + "</qt>")
        self.setAccessibleName(text)

    def setStyleSheet(self, style):  # noqa: N802
        if self.styleSheet() != style:
            super().setStyleSheet(style)

    def setAccessibleName(self, name):  # noqa: N802
        if self.accessibleName() != name:
            super().setAccessibleName(name)

    def setToolTip(self, text):  # noqa: N802
        if self.toolTip() != text:
            super().setToolTip(text)

    def clear(self):
        self.setText("")


def _label(text=""):
    result = _ScanLabel()
    result.setWordWrap(True)
    result.setTextFormat(Qt.TextFormat.PlainText)
    result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    policy = result.sizePolicy()
    policy.setHorizontalPolicy(QSizePolicy.Policy.Ignored)
    policy.setHeightForWidth(True)
    result.setSizePolicy(policy)
    result.setMinimumWidth(0)
    result.setText(text)
    return result


class _ScanToolButton(QToolButton):
    """Keep a scope/disclosure action usable when its full caption will not fit."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def setText(self, text):  # noqa: N802
        super().setText(text)
        self.setAccessibleName(text)
        self.setToolTip("<qt>" + html.escape(text) + "</qt>")

    def minimumSizeHint(self):  # noqa: N802
        hint = super().minimumSizeHint()
        chrome = max(0, super().sizeHint().width() - self.fontMetrics().horizontalAdvance(self.text()))
        hint.setWidth(min(hint.width(), self.fontMetrics().horizontalAdvance("Details…") + chrome))
        return hint

    def paintEvent(self, event):  # noqa: N802
        option = QStyleOptionToolButton()
        self.initStyleOption(option)
        chrome = max(0, super().sizeHint().width() - self.fontMetrics().horizontalAdvance(self.text()))
        option.text = self.fontMetrics().elidedText(self.text(), Qt.TextElideMode.ElideRight,
                                                   max(0, self.width() - chrome))
        painter = QPainter(self)
        self.style().drawComplexControl(QStyle.ComplexControl.CC_ToolButton, option, painter, self)


class _ScanObservedText(QWidget):
    """Compact live observation with exact native selection/copy on disclosure."""

    def __init__(self, kind, text="", parent=None):
        super().__init__(parent)
        self._kind = kind
        self._text = None
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.setAccessibleName(f"Current {kind} text")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        self._header = QWidget()
        self._header.setMinimumWidth(0)
        self._header.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._header_grid = QGridLayout(self._header)
        self._header_grid.setContentsMargins(0, 0, 0, 0)
        self._header_grid.setSpacing(4)
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(False)
        self.summary.setMargin(0)
        self.summary.setIndent(0)
        self.summary.setMinimumWidth(0)
        self.summary.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.summary.installEventFilter(self)
        self.toggle = _ScanToolButton()
        self.toggle.setText("Details…")
        self.toggle.setAccessibleName(f"Show full current {kind} text")
        self.toggle.setCheckable(True)
        self.toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.copy_button = QPushButton(f"Copy {kind}")
        self.copy_button.setAccessibleName(f"Copy full current {kind} text")
        self.copy_button.clicked.connect(self._copy_text)
        self._header_grid.addWidget(self.summary, 0, 0)
        self._header_grid.addWidget(self.toggle, 0, 1)
        self._header_grid.addWidget(self.copy_button, 0, 2)
        self._header_grid.setColumnStretch(0, 1)
        layout.addWidget(self._header)
        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setUndoRedoEnabled(False)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.editor.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.editor.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.editor.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.editor.setMinimumWidth(0)
        self.editor.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.editor.setAccessibleName(f"Full current {kind} text")
        self.editor.hide()
        layout.addWidget(self.editor)
        self.toggle.toggled.connect(self._set_expanded)
        self.setText(text)
        self._sync_geometry()

    def text(self):
        return self._text

    def textFormat(self):  # noqa: N802
        return Qt.TextFormat.PlainText

    def setSelection(self, start, length):  # noqa: N802
        # Match Qt's UTF-16 document offsets, including non-BMP characters.
        limit = max(0, self.editor.document().characterCount() - 1)
        cursor = self.editor.textCursor()
        cursor.setPosition(max(0, min(start, limit)))
        cursor.setPosition(max(0, min(start + length, limit)), QTextCursor.MoveMode.KeepAnchor)
        self.editor.setTextCursor(cursor)

    def selectedText(self):  # noqa: N802
        return self.editor.textCursor().selection().toPlainText()

    def setText(self, text):  # noqa: N802
        if text == self._text:
            return
        self._text = text
        literal_tooltip = "<qt>" + html.escape(text).replace("\n", "<br>") + "</qt>"
        self.setToolTip(literal_tooltip)
        self.summary.setToolTip(literal_tooltip)
        self.summary.setAccessibleName(text)
        cursor = self.editor.textCursor()
        anchor, position = cursor.anchor(), cursor.position()
        scrollbar = self.editor.verticalScrollBar()
        scroll_position = scrollbar.value()
        # Mutate only the existing public document. Never replace its object or
        # inject characters solely to influence line breaking.
        writer = QTextCursor(self.editor.document())
        writer.beginEditBlock()
        writer.select(QTextCursor.SelectionType.Document)
        writer.insertText(text.replace("\r\n", "\n").replace("\r", "\n"))
        writer.endEditBlock()
        limit = max(0, self.editor.document().characterCount() - 1)
        restored = QTextCursor(self.editor.document())
        restored.setPosition(min(anchor, limit))
        restored.setPosition(min(position, limit), QTextCursor.MoveMode.KeepAnchor)
        self.editor.setTextCursor(restored)
        scrollbar.setValue(scroll_position)
        self._fit_summary()

    def _copy_text(self, _checked=False):
        # Copy the retained original, including its original newline characters.
        QApplication.clipboard().setText(self._text)

    def _set_expanded(self, expanded):
        self.editor.setVisible(expanded)
        self.toggle.setArrowType(Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)
        self.toggle.setAccessibleName(f"{'Hide' if expanded else 'Show'} full current {self._kind} text")
        self._sync_geometry()

    def _fit_summary(self):
        if self._text is None:
            return
        mode = Qt.TextElideMode.ElideMiddle if self._kind == "file" else Qt.TextElideMode.ElideRight
        summary_text = self._text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " · ")
        fitted = self.summary.fontMetrics().elidedText(summary_text, mode,
                                                       max(0, self.summary.contentsRect().width()))
        if self.summary.text() != fitted:
            self.summary.setText(fitted)

    def _sync_geometry(self):
        if not hasattr(self, "editor") or getattr(self, "_syncing_geometry", False):
            return
        self._syncing_geometry = True
        try:
            for widget in (self.summary, self.toggle, self.copy_button, self.editor):
                widget.ensurePolished()
            scrollbar = self.editor.verticalScrollBar()
            scroll_position = scrollbar.value()
            height = math.ceil(self.editor.fontMetrics().lineSpacing() * 4
                               + self.editor.document().documentMargin() * 2 + self.editor.frameWidth() * 2)
            if self.editor.minimumHeight() != height:
                self.editor.setFixedHeight(height)
                scrollbar.setValue(scroll_position)
            available = max(0, self.contentsRect().width())
            gap = max(0, self._header_grid.horizontalSpacing())
            caption = self.summary.fontMetrics().horizontalAdvance(f"Current {self._kind}: …")
            details, copy = self.toggle.minimumSizeHint().width(), self.copy_button.minimumSizeHint().width()
            mode = 0 if available >= caption + details + copy + gap * 2 else (
                1 if available >= details + copy + gap else 2)
            if mode != getattr(self, "_header_mode", None):
                self._header_mode = mode
                for widget in (self.summary, self.toggle, self.copy_button):
                    self._header_grid.removeWidget(widget)
                for column in range(3):
                    self._header_grid.setColumnStretch(column, 1 if column == 0 else 0)
                if mode == 0:
                    self._header_grid.addWidget(self.summary, 0, 0)
                    self._header_grid.addWidget(self.toggle, 0, 1)
                    self._header_grid.addWidget(self.copy_button, 0, 2)
                elif mode == 1:
                    self._header_grid.addWidget(self.summary, 0, 0, 1, 2)
                    self._header_grid.addWidget(self.toggle, 1, 0, alignment=Qt.AlignmentFlag.AlignLeft)
                    self._header_grid.addWidget(self.copy_button, 1, 1, alignment=Qt.AlignmentFlag.AlignRight)
                else:
                    self._header_grid.addWidget(self.summary, 0, 0)
                    self._header_grid.addWidget(self.toggle, 1, 0)
                    self._header_grid.addWidget(self.copy_button, 2, 0)
            self._fit_summary()
        finally:
            self._syncing_geometry = False

    def eventFilter(self, watched, event):  # noqa: N802
        if watched is self.summary and event.type() == QEvent.Type.Resize:
            self._fit_summary()
        return super().eventFilter(watched, event)

    def event(self, event):
        result = super().event(event)
        if event.type() in (QEvent.Type.Resize, QEvent.Type.LayoutRequest,
                            QEvent.Type.FontChange, QEvent.Type.StyleChange):
            self._sync_geometry()
        return result


def _literal(value, limit=32768):
    if type(value) in (dict, list, tuple):
        try:
            value = json.dumps(value, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return "Unsupported external result data."
    return str(value if value is not None else "").replace("\x00", "")[:limit]


def _match_summary(report):
    """Present external classifications; this never grants threat authority."""
    if type(report) is not dict:
        return ""
    details = report.get("details")
    details = details if type(details) is dict else {}
    candidates = (details.get("zero_breach"), report, report.get("partial_result"))
    source = next((item for item in candidates if type(item) is dict and type(item.get("match_counts")) is dict), None)
    if source is None:
        return ""
    counts = source["match_counts"]
    names = ("total", "tool_findings", "references", "withdrawn", "displayed", "omitted")
    if (any(type(counts.get(name)) is not int or not 0 <= counts[name] <= 4000 for name in names)
            or counts["total"] != sum(counts[name] for name in ("tool_findings", "references", "withdrawn"))
            or counts["total"] != counts["displayed"] + counts["omitted"]):
        return "Toolkit classification counts unavailable; review the preserved report."
    finding = "tool finding" if counts["tool_findings"] == 1 else "tool findings"
    reference = "contextual reference" if counts["references"] == 1 else "contextual references"
    result = (f"Toolkit report: {counts['tool_findings']} {finding} · {counts['references']} {reference}"
              f" · {counts['withdrawn']} withdrawn.")
    coverage = source.get("coverage_incomplete")
    result += (" Coverage incomplete." if coverage is True else
               " Recorded coverage only." if coverage is False else " Coverage status unavailable.")
    if counts["omitted"]:
        result += f" {counts['displayed']}/{counts['total']} matches displayed; others remain in the original."
    return result + " External matches are unconfirmed; contact does not establish infection."


def _config(manager):
    candidate = getattr(manager, "cfg", None)
    return candidate if candidate is not None else getattr(manager, "config", None)


def _open_link(url):
    # Links come from the maintained catalog or validated source-library names.
    if type(url) is not str or len(url) > 512:
        return
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return
    if (parsed.scheme != "https" or parsed.username or parsed.password or port
            or parsed.hostname not in {"github.com", "archivegenocide.com",
                                       "creativecommons.org", "spdx.org", "learn.microsoft.com",
                                       "raw.githubusercontent.com", "malpedia.caad.fkie.fraunhofer.de"}):
        return
    QDesktopServices.openUrl(QUrl(url))


def _set_enabled(widget, enabled):
    # isEnabled() also includes ancestor state; compare the explicit property.
    if widget.testAttribute(Qt.WidgetAttribute.WA_ForceDisabled) == bool(enabled):
        widget.setEnabled(enabled)


def _set_visible(widget, visible):
    if widget.isHidden() == bool(visible):
        widget.setVisible(visible)


def _set_progress(bar, value, text):
    if bar.value() != value:
        bar.setValue(value)
    if bar.format() != text:
        bar.setFormat(text)


def _set_document_text(editor, text):
    """Change one existing document while retaining its bounded review state."""
    if editor.toPlainText() == text:
        return
    cursor = editor.textCursor()
    anchor, position = cursor.anchor(), cursor.position()
    vertical, horizontal = editor.verticalScrollBar(), editor.horizontalScrollBar()
    top, left = vertical.value(), horizontal.value()
    writer = QTextCursor(editor.document())
    writer.beginEditBlock()
    writer.select(QTextCursor.SelectionType.Document)
    writer.insertText(text)
    writer.endEditBlock()
    limit = max(0, editor.document().characterCount() - 1)
    cursor.setPosition(min(anchor, limit))
    cursor.setPosition(min(position, limit), QTextCursor.MoveMode.KeepAnchor)
    editor.setTextCursor(cursor)
    vertical.setValue(top)
    horizontal.setValue(left)


class _ScanViewPresentation(QObject):
    """Retain one latest status for a view; never gate its controller or jobs."""

    def __init__(self, owner, initial):
        super().__init__(owner)
        self._owner = owner
        self._window = None
        self.latest = initial
        self._pending = False
        self._retired = False
        owner.installEventFilter(self)
        self._watch_window()

    def _watch_window(self):
        window = self._owner.window()
        if window is not self._window:
            if self._window is not None and self._window is not self._owner and isValid(self._window):
                self._window.removeEventFilter(self)
            self._window = window
            if window is not self._owner:
                window.installEventFilter(self)
        return window

    def visible(self):
        if self._retired or not isValid(self._owner):
            return False
        window = self._watch_window()
        return self._owner.isVisible() and window.isVisible() and not window.isMinimized()

    def receive(self, snapshot):
        if self._retired:
            return
        # Controller emissions are already defensive copies. Keep no history or
        # second subscription, and do not read another backend snapshot here.
        self.latest = snapshot
        self._pending = True
        self.flush()

    def flush(self):
        if self._pending and self.visible():
            self._pending = False
            self._owner._apply(self.latest)

    def eventFilter(self, watched, event):  # noqa: N802
        if not isValid(self) or getattr(self, "_retired", True):
            return False
        owner = getattr(self, "_owner", None)
        if owner is None:
            return False
        kind = event.type()
        if kind == QEvent.Type.Destroy and watched is owner:
            self._retired = True
            self._window = None
        elif isValid(owner) and kind in (QEvent.Type.Show, QEvent.Type.WindowStateChange,
                                        QEvent.Type.ParentChange):
            self._watch_window()
            self.flush()
        return False


class CuratedToolsController(QObject):
    """One worker permit and copied publications for every view of the tools."""

    status_changed = Signal(dict)
    credits_ready = Signal(object)
    settings_saved = Signal()
    scan_outcome_ready = Signal(dict)
    _close_after_action_requested = Signal()

    def __init__(self, manager, parent=None, *, service_factory=None):
        super().__init__(parent)
        from angerona.gui.action_progress import ActionActivities
        self.activities = ActionActivities(self)
        self._action_activity = None
        self.manager = manager
        self._factory = service_factory
        self._service = None
        self._service_lock = threading.Lock()
        self._busy = False
        self._closed = False
        self._auto_started = False
        self._operation = None
        self._operation_id = ""
        self._evidence_operation_id = ""
        self._worker = None
        self._pending_priority = None
        self._native_priority_module = None
        self._native_request_id = ""
        self._native_request_generation = None
        self._last_native_completion = None
        self._focus_lease = None
        self._focus_renewed_at = 0.0
        self._completion_dialog = None
        self._storage_dialog = None
        self._next_report_count_limit = None
        self._last_scan_report = None
        self._completion_pending = None
        self._completion_deferred = None
        self._completion_serial = 0
        self._completion_delivered = 0
        self._close_after_action_requested.connect(self._close_after_action)
        self._cancel_requested = threading.Event()
        self._done = threading.Event()
        self._done.set()
        self._frames = queue.Queue(maxsize=32)
        self._terminal_lock = threading.Lock()
        self._terminal_frame = None
        self._snapshot = dict(state="not_loaded", message="Ready to check the pinned scanner.",
                              installed=False, verified=False, version="0.1.10", busy=False)
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._drain)
        self._automatic_timer = QTimer(self)
        self._automatic_timer.timeout.connect(self._automatic_tick)
        self._automatic_due = False
        self._automatic_next_check = 0.0
        self._automatic_probe_snapshot = None

    def snapshot(self):
        return copy.deepcopy(self._snapshot)

    def community_service(self):
        """One lazily constructed backend shared by scanner and tool-hub workers."""
        with self._service_lock:
            if self._closed:
                raise RuntimeError("Curated scanner controller is stopping.")
            if self._service is None:
                backend = _backend()
                factory = self._factory or backend.CuratedToolService
                self._service = factory(cfg=_config(self.manager))
            return self._service

    def _publish(self, **values):
        self._snapshot.update(values)
        self._snapshot["busy"] = self._busy
        if self._action_activity is not None:
            measured = self._snapshot.get("scan_progress")
            measured = measured if type(measured) is dict and measured.get("unit") == "workflow_stages" else {}
            self.activities.update(self._action_activity, label=_literal(self._snapshot.get("message", "Working…"), 240),
                                   done=measured.get("finished", 0), total=measured.get("total", 0))
        self.status_changed.emit(self.snapshot())

    def _frame(self, kind, value):
        if kind in {"result", "error"}:
            # Only the admitted worker publishes one terminal frame. A burst
            # of progress updates must never displace that worker's outcome.
            with self._terminal_lock:
                if not self._closed and self._terminal_frame is None:
                    self._terminal_frame = (kind, value)
            return
        try:
            self._frames.put_nowait((kind, value))
        except queue.Full:
            if kind != "progress":
                # Either progress producer can fill the vacancy before we do.
                try:
                    self._frames.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._frames.put_nowait((kind, value))
                except queue.Full:
                    pass

    def _start(self, action, options=None, *, show_progress=True):
        if self._closed or self._busy or (self._worker is not None and self._worker.is_alive()):
            return False
        self._present_scan_outcome()
        if self._closed or self._busy or (self._worker is not None and self._worker.is_alive()):
            return False  # A completion listener may have stopped or started work.
        cfg = _config(self.manager)
        options = dict(options or {})
        automatic = options.get("_automatic") is True
        if action == "automatic_probe" or automatic:
            self._automatic_probe_snapshot = self.snapshot()
        review_page = options.pop("review_page", 0) if action == "clear_reports" else 0
        budget_setting, default_budget = (
            ("spyware_scan_timeout_seconds", 3600) if action == "priority_scan"
            else ("github_tools_timeout_seconds", 300)
        )
        budget = options.pop("timeout_seconds", getattr(cfg, budget_setting, default_budget))
        if type(budget) is not int or not 30 <= budget <= 14400:
            self._publish(state="held", message="Choose a per-run time budget between 30 and 14400 seconds.")
            return False
        if action in {"prepare", "scan", "priority_scan", "open_tool", "self_test"}:
            if (getattr(self.manager, "ugcap_paused", False)
                    or (action != "priority_scan" and not getattr(cfg, "github_tools_enabled", True))):
                self._publish(state="held", message="Curated scanners are disabled or the workspace is locked.")
                return False
        if action == "settings" and "github_tools_report_count" in options:
            # A newly chosen saved policy supersedes any older reviewed exception,
            # even if persistence fails and the operator must review again.
            self._next_report_count_limit = None
            self._snapshot.pop("next_report_count_limit", None)
        report_count_limit = None
        if action == "scan" or (action == "priority_scan" and not automatic
                and options.get("zero_breach_enabled", getattr(cfg, "spyware_scan_zero_breach_enabled", True))):
            report_count_limit = self._next_report_count_limit
            self._next_report_count_limit = None
            self._snapshot.pop("next_report_count_limit", None)
        if (action in {"scan", "priority_scan", "self_test", "open_tool", "clear_reports", "review_reports"}
                or action == "settings" and {"github_tools_report_count", "github_tools_report_limit_mib"} & options.keys()):
            # A failed or pending review cannot leave old facts eligible for consent.
            self._snapshot.pop("storage", None)
            self._snapshot.pop("storage_reports", None)
        self._busy = True
        if show_progress and action != "status":
            self._action_activity = self.activities.begin("curated-action", action.replace("_", " ").title() + "…", replace=True)
        if action in {"scan", "priority_scan"}:
            self._completion_serial += 1
            # An early failure must not present a previous request's evidence
            # as this run's findings. Saved report files remain untouched.
            for key in ("request_id", "native", "coverage", "findings", "details", "report",
                        "match_counts", "coverage_incomplete", "display_omitted",
                        "partial_result", "error", "native_scan_completion", "review_available", "review_gap",
                        "previous_attempt", "resource_usage", "admin_state", "job_id", "tool",
                        "created_at", "retained_files", "cleanup", "authority", "native_retired",
                        "native_generations", "native_observation_gaps", "timed_out", "stop_reason",
                        "output_dropped", "output_errors", "exit_code", "gap", "native_started", "report_storage",
                        "progress_gap", "job_retained", "storage_hold"):
                self._snapshot.pop(key, None)
            previous = self._snapshot.pop("latest_report", None)
            if previous is not None:
                self._snapshot["previous_saved_report"] = previous
        self._snapshot["active_action"] = action
        self._snapshot["automatic"] = automatic
        self._evidence_operation_id = ""
        self._snapshot["scan_progress"] = None
        self._snapshot["scanner_progress"] = {}
        self._snapshot.pop("focus_lease_gap", None)
        self._snapshot.pop("storage_review_error", None)
        self._snapshot["lifecycle"] = "active"
        self._snapshot["state"] = "running" if action in {"scan", "priority_scan"} else "working"
        self._snapshot["timeout_seconds"] = budget
        started = time.monotonic()
        self._snapshot["started_monotonic"] = started
        self._snapshot["elapsed_seconds"] = 0
        self._cancel_requested.clear()
        self._done.clear()
        self._publish(message={"status": "Checking scanner files…", "prepare": "Preparing the pinned scanner…",
                               "scan": "Starting the selected scan…", "self_test": "Checking the scanner adapter…",
                               "revert": "Reverting the managed scanner…", "open_tool": "Opening the advanced toolkit…",
                               "priority_scan": "Scheduling the selected spyware checks immediately…",
                               "review_reports": "Reviewing retained scanner report receipts…",
                               "export_report": "Exporting the selected recorded report set…",
                               "clear_reports": "Checking selected report custody before explicit deletion…",
                               "settings": "Saving tool settings…", "credits": "Loading project credits…"}.get(action, "Working…"))
        self._timer.start()

        def work():
            backend = None
            operation = None
            outcome = None
            result = None
            try:
                backend = _backend()
                operation = backend.ToolOperation(timeout=budget, **(
                    {"report_count_limit": report_count_limit} if report_count_limit is not None else {}))
                self._operation = operation
                self._operation_id = getattr(operation, "operation_id", "")
                self._evidence_operation_id = self._operation_id
                if self._cancel_requested.is_set():
                    operation.cancel()
                operation.check()
                service = self.community_service()
                progress = lambda message: self._frame("progress", _literal(message, 1000))
                if action == "automatic_probe":
                    from angerona.core.spyware_scan_schedule import AutomaticSpywareScanSchedule
                    decision = AutomaticSpywareScanSchedule(cfg.data_dir).check()
                    result = {"state": decision.status, "reason": decision.reason, "next_due": decision.next_due}
                elif action == "settings":
                    self._save_config(cfg, options or {})
                    result = service.status()
                elif action == "credits":
                    result = self._credits(backend)
                elif action == "scan":
                    result = service.scan(backend.ToolScanRequest(**(options or {})), operation, progress=progress)
                elif action == "priority_scan":
                    result = self._priority_work(backend, service, cfg, operation, options, progress, budget)
                elif action == "prepare":
                    result = service.prepare(operation, progress=progress,
                                             allow_download=bool(getattr(cfg, "github_tools_allow_download", True)),
                                             restore_uninstalled=(options or {}).get("restore_uninstalled") is True)
                elif action == "revert":
                    self._save_config(cfg, {"github_tools_enabled": False, "github_tools_auto_prepare": False})
                    result = service.revert(operation, progress=progress)
                elif action in {"self_test", "open_tool", "clear_reports", "review_reports", "export_report"}:
                    result = getattr(service, action)(operation, progress=progress, **options)
                    if action == "clear_reports" and callable(getattr(service, "review_reports", None)):
                        try:
                            page_options = {"page": review_page} if review_page else {}
                            result = dict(service.review_reports(operation, progress=progress, **page_options), **result)
                        except Exception as error:
                            # Deletion already returned; a later view refresh
                            # cannot turn that completed effect into a retry.
                            result = dict(result, storage_review_error=f"{type(error).__name__}: {_literal(error, 500)}")
                else:
                    result = service.status()
                if action == "scan":
                    operation.check()
                if type(result) is dict:
                    if action in {"scan", "priority_scan"} and "resource_usage" in result:
                        result = dict(result, resource_usage=self._bound_scan_resources(result["resource_usage"]))
                    raw_progress = result.get("scanner_progress")
                    if type(raw_progress) is dict and "operation_id" in raw_progress:
                        result = dict(result)
                        if raw_progress.get("operation_id") == self._operation_id:
                            result["scanner_progress"] = {"toolkit": copy.deepcopy(raw_progress)}
                        else:
                            # A previous job's terminal snapshot is not this run.
                            result.pop("scanner_progress")
                outcome = ("result", (action, result))
            except Exception as error:
                cancelled = self._cancel_requested.is_set()
                deadline = getattr(operation, "deadline", None)
                timed_out = not cancelled and type(deadline) in (int, float) and time.monotonic() >= deadline
                state = "cancelled" if cancelled else "timed-out" if timed_out else "failed"
                reason = f"{type(error).__name__}: {_literal(error, 1200)}"
                failure = dict(state=state, error=reason,
                                          message=(f"Scan time budget reached ({budget}s). Partial progress is preserved. "
                                                   "Review coverage or choose a longer budget for a new run. " if timed_out else
                                                   "Operation cancelled; partial progress is preserved. " if cancelled else
                                                   "Tool operation failed; partial progress is preserved. ") + reason)
                if action == "review_reports":
                    failure["storage_review_error"] = reason
                if type(error) is getattr(backend, "ToolStorageHeld", None):
                    failure.update(state="held", storage_hold=copy.deepcopy(error.storage_hold))
                elif type(error) is getattr(backend, "ToolWorkStorageHeld", None):
                    failure["storage_hold"] = copy.deepcopy(error.storage_hold)
                    if not (cancelled or timed_out):
                        failure["state"] = "held"
                if (action not in {"review_reports", "export_report", "clear_reports"}
                        and not (timed_out or cancelled or type(error) in (
                            getattr(backend, "ToolStorageHeld", None), getattr(backend, "ToolWorkStorageHeld", None)))):
                    failure["verified"] = False
                if type(result) is dict:
                    failure["partial_result"] = result
                outcome = ("error", failure)
            finally:
                # A returned scan/exception is not native child retirement.
                # Keep admission closed and the owner alive until its exact
                # backend custody has actually drained. No Qt waits or kills.
                if action != "automatic_probe":
                    self._retain_tool_progress()
                wait = (getattr(self._service, "wait_for_shutdown", None)
                        if action != "automatic_probe" else None)
                if callable(wait):
                    while True:
                        try:
                            retired = wait(.1)
                        except Exception:
                            retired = False
                        if retired is True:
                            break
                        self._frame("metadata", {"lifecycle": "draining", "state": "stopping",
                                                 "message": "Stopping · owned toolkit process retirement is still pending."})
                        self._retain_tool_progress()
                        time.sleep(.1)
                self._operation = None
                self._operation_id = ""
                if outcome is not None:
                    self._frame("metadata", {"elapsed_seconds": max(0, time.monotonic() - started)})
                    self._frame(*outcome)
                self._done.set()

        try:
            self._worker = threading.Thread(target=work, name="AngeronaCuratedTools", daemon=True)
            self._worker.start()
        except Exception as error:
            if self._worker is not None and self._worker.is_alive():
                self._cancel_current()
                self._publish(message="Worker startup acknowledgment failed; waiting for its owned work to retire.")
                return False
            self._worker = None
            if action == "automatic_probe" or automatic:
                self._done.set()
                self._apply_automatic_probe("error", None)
                return False
            failure = dict(state="failed", message="The tool worker could not start; no scan completion was established.",
                           error=f"{type(error).__name__}: {_literal(error, 700)}")
            self._queue_scan_outcome(action, failure)
            self._busy = False
            self._done.set()
            self._publish(**failure, lifecycle="terminal")
            self._present_scan_outcome()
            return False
        return True

    def _retain_tool_progress(self):
        read = getattr(self._service, "progress_snapshot", None)
        if not callable(read) or not self._operation_id:
            return
        try:
            value = read()
            if type(value) is dict and value.get("operation_id") == self._operation_id:
                self._frame("scanner", ("toolkit", copy.deepcopy(value)))
        except Exception:
            pass  # Retain the last publication; missing status is not completion.

    def _bound_scan_resources(self, value):
        if (type(value) is dict and self._evidence_operation_id
                and value.get("operation_id") == self._evidence_operation_id):
            return copy.deepcopy(value)
        return {"state": "unavailable", "reason": "No toolkit resource sample is bound to this scan operation."}

    def _priority_work(self, backend, service, cfg, operation, options, progress, budget=300):
        automatic = options.pop("_automatic", False) is True
        if automatic:
            from angerona.core.spyware_scan_schedule import AutomaticSpywareScanSchedule
            scope = options.pop("_schedule_scope")
            operation.check()
            if (getattr(cfg, "spyware_scan_auto_enabled", True) is not True
                    or getattr(cfg, "spyware_scan_auto_scope", "full") != scope):
                return {"state": "schedule-held", "message": "Automatic scan settings changed."}
            decision = AutomaticSpywareScanSchedule(cfg.data_dir).claim(scope=scope)
            operation.check()
            if (decision.status != "claimed" or self._closed
                    or getattr(cfg, "spyware_scan_auto_enabled", True) is not True
                    or getattr(cfg, "spyware_scan_auto_scope", "full") != scope):
                return {"state": "schedule-held", "message": "Automatic scan held. " + decision.reason}
        request_id = uuid.uuid4().hex
        deadline = time.monotonic() + budget
        if hasattr(operation, "deadline"):
            operation.deadline = min(operation.deadline, deadline)
        native_enabled = bool(options.pop("native_enabled", getattr(cfg, "spyware_scan_native_enabled", True)))
        tool_enabled = bool(options.pop("zero_breach_enabled", getattr(cfg, "spyware_scan_zero_breach_enabled", True)))
        if not native_enabled and not tool_enabled:
            raise ValueError("Select at least one spyware scanner.")
        options.setdefault("priority", getattr(cfg, "spyware_scan_priority", "above-normal"))
        options.setdefault("max_cpu_percent", getattr(cfg, "spyware_scan_cpu_percent", 70))
        options.setdefault("max_memory_mib", getattr(cfg, "spyware_scan_memory_mib", 512))
        if automatic:
            options["priority"] = "normal"
            options["max_cpu_percent"] = min(25, options["max_cpu_percent"])
        modules = getattr(self.manager, "modules", {})
        native = modules.get("SpywareGuard") if type(modules) is dict else None
        native_state = dict(state="disabled", coverage="Native scan not selected.")
        tool_result = dict(state="disabled", coverage="Zero-Breach not selected.")
        completed_stages = set()
        total_stages = 2 + int(native_enabled) + int(tool_enabled)

        def scan_progress(stage, *, terminal=False):
            return dict(request_id=request_id, unit="workflow_stages", stage=stage,
                        finished=len(completed_stages), total=total_stages,
                        planned_stages=("preflight",) + (("native",) if native_enabled else ())
                        + (("toolkit",) if tool_enabled else ()) + ("aggregation",),
                        finished_stages=tuple(sorted(completed_stages)),
                        state="finished" if terminal else "running",
                        native_state=native_state.get("state", "unavailable"),
                        tool_state=tool_result.get("state", "unavailable"))

        def publish_stage(stage):
            self._frame("metadata", {"scan_progress": scan_progress(stage)})

        publish_stage("preflight")
        focus = getattr(self.manager, "priority_scan_focus", None)
        lease = focus(owner=request_id, background_percent=getattr(cfg, "spyware_scan_background_percent", 10)) if callable(focus) and not automatic else contextlib.nullcontext()
        self._native_request_id = request_id
        self._native_request_generation = None
        self._last_native_completion = None
        try:
            with self._focus_scope(lease, request_id) as active_lease:
                self._focus_lease = active_lease
                self._focus_renewed_at = time.monotonic()
                if native_enabled:
                    if native is not None and callable(getattr(native, "request_priority_scan", None)):
                        try:
                            with self._terminal_lock:
                                if self._closed or self._cancel_requested.is_set():
                                    operation.cancel()
                                operation.check()
                                scoped = getattr(native, "request_scoped_priority_scan", None)
                                mode = options.get("mode", "default")
                                if callable(scoped):
                                    admitted = scoped(request_id, mode=mode, targets=options.get("targets", ()),
                                                      background=automatic)
                                else:
                                    admitted = (not automatic and mode in {"default", "full"}
                                                and native.request_priority_scan(request_id))
                                if admitted:
                                    self._native_priority_module = native
                            if admitted:
                                self._bind_native_generation(native.priority_scan_snapshot())
                                native_state = dict(state="queued", request_id=request_id)
                                progress("Native SpywareGuard scan scheduled; preparing selected toolkit checks.")
                            else:
                                native_state = dict(state="held", coverage="Native scanner could not admit this request.")
                        except Exception as error:
                            native_state = dict(state="failed", error=f"{type(error).__name__}: {_literal(error, 300)}")
                    else:
                        native_state = dict(state="unavailable", coverage="Native priority-scanning interface is unavailable.")
                operation.check()
                checked_status = None
                if getattr(cfg, "spyware_scan_verify_admin", True):
                    checked_status = service.status()
                    self._frame("metadata", {"admin_state": checked_status.get("admin_state", {"verified": False})})
                completed_stages.add("preflight")
                if native_enabled and self._native_priority_module is None:
                    completed_stages.add("native")
                publish_stage("toolkit" if tool_enabled else "native")
                if tool_enabled:
                    if not getattr(cfg, "github_tools_enabled", True):
                        tool_result = dict(state="disabled", coverage="Curated scanner integrations are disabled in settings.")
                    else:
                        tool_status = checked_status or service.status()
                        if tool_status.get("execution_available") is False:
                            tool_result = dict(state="unavailable", coverage={"held": tool_status.get(
                                "execution_hold_reason", "An unprivileged scanner runtime is unavailable.")})
                        else:
                            if not tool_status.get("verified"):
                                operation.check()
                                service.prepare(operation, progress=progress,
                                                allow_download=bool(getattr(cfg, "github_tools_allow_download", True)))
                            operation.check()
                            try:
                                tool_result = service.scan(backend.ToolScanRequest(**options), operation, progress=progress)
                            except Exception as error:
                                if type(error) is not getattr(backend, "ToolWorkStorageHeld", None):
                                    raise  # Source, custody and unknown failures retain strict cleanup.
                                operation.check()  # A storage observation never overrides STOP/deadline.
                                hold = copy.deepcopy(error.storage_hold)
                                tool_result = dict(state="held", tool_worker_started=False,
                                    coverage_incomplete=True, message=str(error), storage_hold=hold,
                                    findings=[], coverage={"state": "not-started", "storage_hold": hold})
                                self._frame("metadata", {"storage_hold": hold})
                                progress("Zero-Breach is held by free space; native SpywareGuard checks continue.")
                            self._frame("metadata", {"partial_result": tool_result})
                            operation.check()
                    completed_stages.add("toolkit")
                    publish_stage("native" if self._native_priority_module is not None else "aggregation")
                if self._native_priority_module is not None:
                    while True:
                        operation.check()
                        native_state = native.priority_scan_snapshot()
                        if self._native_snapshot_exact(native_state):
                            self._frame("scanner", ("native", native_state.get("progress", {})))
                        if not self._native_snapshot_exact(native_state):
                            native_state = dict(state="incomplete", error="The native scan generation changed; its result was not accepted.")
                            break
                        if native_state.get("state") not in {"queued", "running"}:
                            break
                        if time.monotonic() >= deadline:
                            native.cancel_priority_scan(request_id)
                            native_state = dict(native_state, state="incomplete", error="Native scan exceeded its deadline.")
                            break
                        operation.cancelled.wait(.1)
                    completed_stages.add("native")
                publish_stage("aggregation")
            if self._last_native_completion is not None:
                native_state = self._last_native_completion
            incomplete = native_enabled and (native_state.get("state") != "completed"
                                             or native_state.get("coverage_incomplete") is True)
            incomplete = incomplete or (tool_enabled and (
                tool_result.get("coverage_incomplete") is True
                or tool_result.get("state") not in {"complete", "findings", "references", "withdrawn"}))
            completed_stages.add("aggregation")
            result = dict(state="incomplete" if incomplete else "completed",
                        message=("Spyware scan ended with incomplete coverage. Review each scanner's findings and gaps."
                                 if incomplete else "Spyware scan finished. Review each scanner's findings and coverage."),
                        request_id=request_id, native=native_state, coverage={"native": native_state, "zero_breach": tool_result.get("coverage")},
                        findings=tool_result.get("findings", []), report=tool_result.get("report"),
                         match_counts=tool_result.get("match_counts"), coverage_incomplete=incomplete,
                        details={"native": native_state, "zero_breach": tool_result},
                        scan_progress=scan_progress("finished", terminal=True))
            if self._last_native_completion is not None:
                result["native_scan_completion"] = self._last_native_completion
            if type(tool_result.get("storage_hold")) is dict:
                result["storage_hold"] = copy.deepcopy(tool_result["storage_hold"])
            if options.get("mode") == "full" and native_enabled:
                observed = {}
                for key, name, member in (
                    ("automation", "Counter-Agentic Detection", "behavior_snapshot"),
                    ("accessories", "Peripheral and DMA Posture Guard", "accessory_scan_snapshot"),
                ):
                    reader = getattr(modules.get(name), member, None) if type(modules) is dict else None
                    try:
                        observed[key] = reader() if callable(reader) else {"state": "unavailable"}
                    except Exception:
                        observed[key] = {"state": "unavailable"}
                result["details"]["cached_host_observations"] = observed
            return result
        except Exception as error:
            # Exiting the focus scope has already settled the exact native
            # request. An optional toolkit refusal must not leave this run's
            # copied overall state looking active or replace that completion
            # with the earlier queued snapshot.
            if self._last_native_completion is not None:
                native_state = copy.deepcopy(self._last_native_completion)
                completed_stages.add("native")
            cancelled = operation.cancelled.is_set()
            timed_out = not cancelled and time.monotonic() >= operation.deadline
            storage = (copy.deepcopy(error.storage_hold)
                       if type(error) is getattr(backend, "ToolStorageHeld", None) else None)
            state = "cancelled" if cancelled else "timed-out" if timed_out else "held" if storage else "failed"
            reason = f"{type(error).__name__}: {_literal(error, 1200)}"
            if tool_enabled and tool_result.get("state") == "disabled":
                tool_result = {"state": "not-started" if storage else state,
                               "coverage": "Toolkit work did not complete: " + reason}
            readers = {}
            if self._last_native_completion is not None:
                readers["native"] = copy.deepcopy(native_state.get("progress", {}))
            read = getattr(service, "progress_snapshot", None)
            if callable(read):
                try:
                    value = read()
                    if type(value) is dict and value.get("operation_id") == self._operation_id:
                        readers["toolkit"] = copy.deepcopy(value)
                except Exception:
                    pass  # A missing reader is an explicit gap, not completion.
            result = dict(state=state, error=reason,
                message=(f"Scan time budget reached ({budget}s). Partial progress is preserved. "
                         "Review coverage or choose a longer budget for a new run. " if timed_out else
                         "Toolkit storage needs review; selected work ended with incomplete coverage. "
                         "No evidence was deleted. " if storage else
                         "Spyware Scan ended before all selected work completed. Partial evidence is retained. ") + reason,
                request_id=request_id, native=native_state,
                coverage={"native": native_state, "zero_breach": tool_result.get("coverage")},
                coverage_incomplete=True, findings=tool_result.get("findings", []),
                details={"native": native_state, "zero_breach": tool_result},
                scan_progress=dict(scan_progress("finished", terminal=True), state=state),
                scanner_progress=readers)
            if self._last_native_completion is not None:
                result["native_scan_completion"] = self._last_native_completion
            if storage:
                result["storage_hold"] = storage
            elif not (cancelled or timed_out):
                result["verified"] = False
            return result
        finally:
            # _focus_scope retains the exact native request until terminal.
            self._native_priority_module = None
            self._native_request_id = ""
            self._native_request_generation = None
            self._focus_lease = None

    def _bind_native_generation(self, snapshot):
        if (self._native_request_generation is None and type(snapshot) is dict
                and snapshot.get("request_id") == self._native_request_id
                and type(snapshot.get("lifecycle_generation")) is int
                and snapshot["lifecycle_generation"] > 0):
            self._native_request_generation = snapshot["lifecycle_generation"]

    def _native_snapshot_exact(self, snapshot):
        return (type(snapshot) is dict and snapshot.get("request_id") == self._native_request_id
                and type(snapshot.get("lifecycle_generation")) is int
                and self._native_request_generation is not None
                and snapshot["lifecycle_generation"] == self._native_request_generation)

    @contextlib.contextmanager
    def _focus_scope(self, lease, request_id):
        with lease as active:
            try:
                yield active
            finally:
                native = self._native_priority_module
                if native is not None:
                    requested = False
                    while True:
                        try:
                            snapshot = native.priority_scan_snapshot()
                        except Exception:
                            snapshot = {"state": "unavailable"}
                        self._bind_native_generation(snapshot)
                        exact = self._native_snapshot_exact(snapshot)
                        if (exact and snapshot.get("state") in {"completed", "cancelled", "failed"}
                                and snapshot.get("request_finished") is True
                                and snapshot.get("collector_finished") is True):
                            self._last_native_completion = copy.deepcopy(snapshot)
                            self._frame("scanner", ("native", snapshot.get("progress", {})))
                            self._frame("metadata", {"native_scan_completion": snapshot})
                            break
                        if not requested:
                            try:
                                native.cancel_priority_scan(request_id)
                                requested = True
                            except Exception:
                                pass
                        self._frame("metadata", {"lifecycle": "draining", "state": "stopping",
                                                 "message": "Stopping · the exact native check is still retiring. New scans are held."})
                        if exact:
                            self._frame("scanner", ("native", snapshot.get("progress", {})))
                        renew = getattr(active, "renew", None)
                        if callable(renew) and time.monotonic() - self._focus_renewed_at >= 10:
                            self._focus_renewed_at = time.monotonic()
                            try:
                                renewed = renew()
                            except Exception as error:
                                renewed = False
                                self._frame("metadata", {"focus_lease_gap": f"Focus renewal unavailable: {type(error).__name__}; exact native request remains owned."})
                            if renewed is not True:
                                self._frame("metadata", {"focus_lease_gap": "Focus renewal could not be verified; exact native request remains held until completion."})
                        time.sleep(.1)

    @staticmethod
    def _save_config(cfg, options):
        if cfg is None:
            raise ValueError("Tool settings are unavailable.")
        values = {}
        for name in _SETTINGS:
            if name in options:
                if type(options[name]) is not bool:
                    raise ValueError("Invalid scanner setting.")
                values[name] = options[name]
        for name, (_title, _default, low, high) in _LIMITS.items():
            if name in options:
                if type(options[name]) is not int or not low <= options[name] <= high:
                    raise ValueError("Invalid scanner storage or deadline limit.")
                values[name] = options[name]
        if "github_tools_report_count" in options:
            count = options["github_tools_report_count"]
            if not valid_scanner_report_count(count):
                raise ValueError("Choose Unlimited or a valid finite scanner report count.")
            values["github_tools_report_count"] = count
        if "spyware_scan_priority" in options:
            if options["spyware_scan_priority"] not in {"above-normal", "high"}:
                raise ValueError("Unsupported spyware scan priority.")
            values["spyware_scan_priority"] = options["spyware_scan_priority"]
        if "spyware_scan_auto_enabled" in options:
            enabled = options["spyware_scan_auto_enabled"]
            if type(enabled) is not bool:
                raise ValueError("Automatic scan preference must be on or off.")
            values["spyware_scan_auto_enabled"] = enabled
        if "spyware_scan_auto_scope" in options:
            from angerona.core.config import SPYWARE_SCAN_AUTO_SCOPES
            scope = options["spyware_scan_auto_scope"]
            if type(scope) is not str or scope not in SPYWARE_SCAN_AUTO_SCOPES:
                raise ValueError("Unsupported automatic spyware scan scope.")
            values["spyware_scan_auto_scope"] = scope
        candidate = copy.deepcopy(cfg)
        for name, value in values.items():
            setattr(candidate, name, value)
        candidate.save()
        for name, value in values.items():
            setattr(cfg, name, value)

    @staticmethod
    def _credits(backend):
        rows = list(backend.credits())
        try:
            from angerona.core.data_paths import data_dir
            from angerona.core.github_tool_catalog import GitHubToolCatalog, repository_identity
            for item in GitHubToolCatalog(data_dir() / "github-source-library").list_imports():
                repository = repository_identity("https://github.com/" + item["repository"])
                rows.append(dict(name=repository, url="https://github.com/" + repository,
                                 version=item["commit"], license=item["license"],
                                 notice="Source-library attribution metadata; review does not authorize execution."))
        except Exception:
            rows.append(dict(name="Source library", notice="Source-library credits are currently unavailable."))
        return rows[:64]

    def _drain(self):
        if not self._closed and self._busy:
            self._retain_tool_progress()
            lease = self._focus_lease
            if lease is not None and time.monotonic() - self._focus_renewed_at >= 10:
                renew = getattr(lease, "renew", None)
                try:
                    if callable(renew) and renew():
                        self._focus_renewed_at = time.monotonic()
                except Exception:
                    pass
            usage = {}
            if self._service is not None and callable(getattr(self._service, "resource_snapshot", None)):
                try:
                    usage = self._service.resource_snapshot()
                    if type(usage) is not dict:
                        usage = {"state": "unavailable"}
                    if self._snapshot.get("active_action") in {"scan", "priority_scan"}:
                        usage = self._bound_scan_resources(usage)
                except Exception:
                    usage = {"state": "unavailable"}
            native = self._native_priority_module
            if native is not None:
                try:
                    native_snapshot = native.priority_scan_snapshot()
                    if self._native_snapshot_exact(native_snapshot):
                        usage = dict(usage, native=native_snapshot)
                        self._frame("scanner", ("native", native_snapshot.get("progress", {})))
                    else:
                        usage = dict(usage, native={"state": "unavailable",
                                                   "reason": "The native scan generation changed."})
                except Exception:
                    usage = dict(usage, native={"state": "unavailable"})
            if usage and usage != self._snapshot.get("resource_usage"):
                self._publish(resource_usage=usage)
        # Capture the terminal frame before draining progress. When captured,
        # the worker has finished publishing every preceding progress frame.
        with self._terminal_lock:
            terminal, self._terminal_frame = self._terminal_frame, None
        for _ in range(32):
            try:
                kind, value = self._frames.get_nowait()
            except queue.Empty:
                break
            if self._closed:
                continue
            if kind == "progress":
                self._publish(message=value)
            elif kind == "metadata":
                self._publish(**value)
            elif kind == "scanner":
                source, progress = value
                if type(progress) is dict and progress:
                    combined = dict(self._snapshot.get("scanner_progress") or {})
                    combined[source] = copy.deepcopy(progress)
                    if combined != self._snapshot.get("scanner_progress"):
                        self._publish(scanner_progress=combined)
        if terminal is not None and not self._closed:
            kind, value = terminal
            if self._snapshot.get("active_action") == "automatic_probe":
                self._apply_automatic_probe(kind, value)
            elif (self._snapshot.get("automatic") is True and kind == "result"
                  and value[1].get("state") == "schedule-held"):
                self._apply_automatic_probe("result", ("automatic_probe", {
                    "state": "held", "reason": value[1].get("message", "Automatic scan held."),
                }))
            elif kind == "error":
                self._automatic_probe_snapshot = None
                self._queue_scan_outcome(self._snapshot.get("active_action"), value)
                self._busy = False
                self._publish(**value, lifecycle="terminal")
            else:
                action, result = value
                self._automatic_probe_snapshot = None
                self._busy = False
                if action == "credits":
                    if self._pending_priority is None:
                        self.credits_ready.emit(result)
                    self._publish(message="Project credits loaded.")
                else:
                    update = result if type(result) is dict else dict(message=_literal(result))
                    self._queue_scan_outcome(action, update)
                    self._publish(**dict(update, lifecycle="terminal"))
                    if action == "settings":
                        self._automatic_next_check = 0.0
                        self._automatic_due = False
                        self.settings_saved.emit()
        self._present_scan_outcome()
        if not self._busy and self._pending_priority is not None:
            # A result publication is not thread retirement. Reuse the one
            # worker permit only after its actual Python thread has exited;
            # the backend separately retains native child-tree custody.
            if self._worker is None or not self._worker.is_alive():
                options, self._pending_priority = self._pending_priority, None
                pending, self._completion_pending = self._completion_pending, None
                if pending is not None:
                    previous = copy.deepcopy(pending[1])
                    previous.pop("previous_attempt", None)
                    self._completion_deferred = previous
                if not self._start("priority_scan", options) and pending is not None:
                    self._completion_deferred = None
                    self._completion_pending = pending
                    self._present_scan_outcome()
            return
        worker_retired = self._worker is None or not self._worker.is_alive()
        if not self._busy and worker_retired:
            self.activities.finish(self._action_activity)
            self._action_activity = None
        if not self._busy and worker_retired and self._frames.empty() and self._completion_pending is None:
            self._timer.stop()

    def _queue_scan_outcome(self, action, values):
        if (not self._closed and action in {"scan", "priority_scan"}
                and values.get("state") != "schedule-held"
                and self._completion_serial > self._completion_delivered):
            # Deliberately allowlist current-run metadata. A new adapter field
            # from an old run cannot become an early failure's custody proof.
            keys = ("active_action", "scan_progress", "scanner_progress", "timeout_seconds",
                    "started_monotonic", "elapsed_seconds", "resource_usage", "admin_state",
                    "native_scan_completion", "focus_lease_gap", "partial_result", "version")
            report = {key: copy.deepcopy(self._snapshot[key]) for key in keys if key in self._snapshot}
            report.update(copy.deepcopy(values))
            report.update(busy=False, lifecycle="terminal")
            report["review_attempt"] = self._completion_serial
            report["automatic"] = self._snapshot.get("automatic") is True
            if self._evidence_operation_id:
                report["operation_id"] = self._evidence_operation_id
            if self._completion_deferred is not None:
                report["previous_attempt"] = copy.deepcopy(self._completion_deferred)
                self._completion_deferred = None
            self._completion_pending = (self._completion_serial, report)
            self._last_scan_report = copy.deepcopy(report)

    def _present_scan_outcome(self):
        if (self._closed or self._busy or self._pending_priority is not None or self._completion_pending is None
                or (self._worker is not None and self._worker.is_alive())):
            return
        serial, report = self._completion_pending
        self._completion_pending = None
        if serial <= self._completion_delivered:
            return
        self._completion_delivered = serial
        if report.get("automatic") is True:
            self._publish(review_available=True, review_gap=None)
        else:
            self._open_scan_report(report)
        if not self._closed:
            self.scan_outcome_ready.emit(copy.deepcopy(report))

    def _open_scan_report(self, report=None, *, activate=False):
        try:
            dialog = self.show_after_action(report)
            if dialog is None:
                raise RuntimeError("Report presentation is unavailable")
            if activate:
                dialog.activateWindow()
        except Exception as error:
            self._publish(review_available=True,
                          review_gap=f"After-action window could not open ({type(error).__name__}). Open the retained report to retry.")
            return None
        self._publish(review_available=True, review_gap=None)
        return dialog

    def retained_scan_attempt(self):
        report = self._last_scan_report
        attempt = report.get("review_attempt") if type(report) is dict else None
        return attempt if type(attempt) is int and attempt > 0 else None

    def open_retained_scan_report(self, *, expected_attempt=None):
        if (expected_attempt is not None and self.retained_scan_attempt() != expected_attempt):
            return None
        if (self._closed or self._busy or QThread.currentThread() != self.thread()
                or self._snapshot.get("review_available") is not True or self._last_scan_report is None):
            return None
        return self._open_scan_report(activate=True)

    def show_after_action(self, report=None, *, trace=False):
        """One literal, nonmodal report shared by every scanner view."""
        if self._closed or QThread.currentThread() != self.thread():
            return None
        from angerona.gui.breach_display import AfterActionReportDialog
        from angerona.gui.window_fit import install_window_fit
        from angerona.gui.window_controls import configure_work_window
        last_completed = report is None and self._last_scan_report is not None
        report = copy.deepcopy(self._last_scan_report or self._snapshot) if report is None else copy.deepcopy(report)
        dialog = self._completion_dialog
        if dialog is None or not isValid(dialog):
            # Bind the existing main window's group/qualified breach outline
            # without importing or constructing another security dashboard.
            parents = [widget for widget in QApplication.topLevelWidgets()
                       if type(widget).__module__ == "angerona.gui.main_window"
                       and type(widget).__name__ == "MainWindow"
                       and getattr(widget, "manager", None) is self.manager]
            parent = parents[0] if len(parents) == 1 else None
            dialog = AfterActionReportDialog(report, parent, confirmed=False, scanner_review=True)
            dialog.setModal(False)
            configure_work_window(dialog)
            dialog.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
            install_window_fit(dialog, scroll_content=True)
            storage = QPushButton("Review scanner storage…", dialog)
            storage.clicked.connect(self.show_storage_review)
            dialog.layout().addWidget(storage)
            dialog.scanner_storage_button = storage
            self._completion_dialog = dialog
        else:
            dialog.update_report(report, confirmed=False)
        summary = _match_summary(report)
        dialog.notice.setText("Spyware scan review · " + ("last completed attempt · " if last_completed else "")
                              + _literal(report.get("state", "unknown"), 80)
                              + ". Review native coverage and toolkit leads; completion does not establish a clean PC."
                              + ("\n" + summary if summary else ""))
        if trace:
            dialog.show_trace()
        else:
            dialog.show_investigation()
        dialog.show()
        dialog.raise_()
        return dialog

    @Slot()
    def _close_after_action(self):
        if self._closed:
            self._automatic_timer.stop()
        self.activities.close()
        self._action_activity = None
        self._timer.stop()
        storage, self._storage_dialog = self._storage_dialog, None
        if storage is not None and isValid(storage):
            storage.close()
            storage.deleteLater()
        dialog, self._completion_dialog = self._completion_dialog, None
        if dialog is not None and isValid(dialog):
            dialog.close()
            dialog.deleteLater()

    def refresh(self):
        return self._start("status")

    def prepare(self):
        return self._start("prepare", {"restore_uninstalled": True})

    def scan(self, **options):
        return self._start("scan", options)

    def priority_scan(self, **options):
        if self._closed:
            return False
        if self._busy:
            if (self._snapshot.get("active_action") == "priority_scan"
                    and self._snapshot.get("automatic") is not True):
                self._publish(message="The dedicated spyware scan is already scheduled or running at its selected priority.")
                return True
            if self._pending_priority is None:
                self._pending_priority = dict(options)
            self._cancel_current()
            self._publish(message="Priority scan queued; finishing and retiring the current owned tool operation…")
            return True
        return self._start("priority_scan", options)

    def self_test(self):
        return self._start("self_test")

    def open_tool(self):
        return self._start("open_tool")

    def revert(self):
        return self._start("revert")

    def clear_reports(self, expected=None, *, page=0):
        if type(page) is not int or page < 0:
            return False
        options = {"expected": expected, "review_page": page} if expected is not None else {}
        return self._start("clear_reports", options)

    def allow_next_report(self, *, retained_reports, accepted=False):
        """Arm one explicit scan attempt; never save preferences or start work."""
        if (accepted is not True or self._closed or self._busy
                or QThread.currentThread() != self.thread()):
            return False
        choice = _extra_report_choice(self._snapshot)
        if (choice is None or type(retained_reports) is not int
                or retained_reports != choice[0]):
            return False
        self._next_report_count_limit = choice[1]
        self._publish(next_report_count_limit=choice[1],
            message=f"Next scan may retain up to {choice[1]} report sets once. "
                    "Settings and existing evidence are unchanged; byte and free-space checks still apply. "
                    "Choose Scan when ready.")
        return True

    def review_reports(self, *, page=0):
        if type(page) is not int or page < 0:
            return False
        return self._start("review_reports", {"page": page} if page else None)

    def export_report(self, *, job_id, expected_receipt, destination):
        return self._start("export_report", {"job_id": job_id, "expected_receipt": expected_receipt,
                                              "destination": destination})

    def show_storage_review(self):
        if self._closed or QThread.currentThread() != self.thread():
            return None
        dialog = self._storage_dialog
        if dialog is None or not isValid(dialog):
            dialog = self._storage_dialog = ScannerStorageDialog(self)
        dialog.show()
        dialog.raise_()
        if not self._busy:
            self.review_reports()
        return dialog

    def load_credits(self):
        return self._start("credits")

    def save_options(self, values):
        return self._start("settings", dict(values))

    def cancel(self):
        self._next_report_count_limit = None
        self._snapshot.pop("next_report_count_limit", None)
        self._pending_priority = None
        self._cancel_current()
        progress = self._snapshot.get("scan_progress")
        if type(progress) is dict:
            progress = dict(progress, stage="cancelling", state="cancelling")
        self._publish(message="Cancellation requested; waiting for owned tool retirement…",
                      scan_progress=progress)

    def _cancel_current(self):
        with self._terminal_lock:
            self._cancel_requested.set()
            operation = self._operation
            native = self._native_priority_module
            request_id = self._native_request_id
        if operation is not None:
            operation.cancel()
        if native is not None:
            native.cancel_priority_scan(request_id)

    def start_automatic_schedule(self):
        if not self._closed and not self._automatic_timer.isActive():
            self._automatic_timer.start(120_000)

    def _automatic_tick(self):
        if self._closed:
            return
        if self._automatic_timer.interval() != 60_000:
            self._automatic_timer.start(60_000)
        cfg = _config(self.manager)
        if (self._closed or self._busy or self._pending_priority is not None
                or (self._worker is not None and self._worker.is_alive())
                or QApplication.activeModalWidget() is not None
                or getattr(self.manager, "ugcap_paused", False)
                or getattr(cfg, "spyware_scan_auto_enabled", True) is not True
                or not (getattr(cfg, "spyware_scan_native_enabled", True)
                        or getattr(cfg, "spyware_scan_zero_breach_enabled", True))
                or time.monotonic() < self._automatic_next_check):
            return
        scope = getattr(cfg, "spyware_scan_auto_scope", "full")
        if not self._automatic_due:
            self._start("automatic_probe", show_progress=False)
            return
        if type(scope) is not str or scope not in {"full", "browser", "quick"}:
            return
        options = {"_automatic": True, "_schedule_scope": scope,
                   "mode": "default" if scope == "quick" else scope, "quick": scope == "quick"}
        if self._start("priority_scan", options, show_progress=False):
            self._automatic_due = False
            self._automatic_next_check = time.monotonic() + 3600

    def _apply_automatic_probe(self, kind, value):
        previous, self._automatic_probe_snapshot = self._automatic_probe_snapshot, None
        self._busy = False
        if previous is not None:
            previous.pop("next_report_count_limit", None)
            if self._next_report_count_limit is not None:
                previous["next_report_count_limit"] = self._next_report_count_limit
            self._snapshot = previous
        result = value[1] if kind == "result" else {"state": "held", "reason": "Schedule check unavailable."}
        self._automatic_due = result.get("state") == "due"
        due = result.get("next_due")
        delay = 0 if self._automatic_due else max(60, min(86400, due - time.time())) if type(due) is int else 3600
        self._automatic_next_check = time.monotonic() + delay
        self._publish(automatic_schedule=result)

    def auto_prepare(self):
        cfg = _config(self.manager)
        if (self._auto_started or self._closed or not getattr(cfg, "github_tools_enabled", True)
                or not getattr(cfg, "github_tools_auto_prepare", True)):
            return False
        self._auto_started = True
        return self._start("prepare", show_progress=False)

    def shutdown(self):
        self._next_report_count_limit = None
        self._snapshot.pop("next_report_count_limit", None)
        with self._terminal_lock:
            self._closed = True
            self._terminal_frame = None
        self._pending_priority = None
        self._completion_pending = None
        self._completion_deferred = None
        self._close_after_action_requested.emit()
        self._cancel_requested.set()
        if self._operation is not None:
            self._operation.cancel()
        native = self._native_priority_module
        if native is not None:
            native.cancel_priority_scan(self._native_request_id)
        service = self._service
        if service is not None and callable(getattr(service, "cancel_all", None)):
            service.cancel_all()

    def wait_for_shutdown(self, timeout=5.0):
        deadline = time.monotonic() + max(0, timeout)
        if not self._done.wait(max(0, deadline - time.monotonic())):
            return False
        worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(max(0, deadline - time.monotonic()))
            if worker.is_alive():
                return False
        service = self._service
        wait = getattr(service, "wait_for_shutdown", None) if service is not None else None
        return bool(wait(max(0, deadline - time.monotonic()))) if callable(wait) else True


def get_curated_tools_controller(manager):
    controller = getattr(manager, "_curated_tools_controller", None)
    if not isinstance(controller, CuratedToolsController):
        controller = CuratedToolsController(manager, QApplication.instance())
        manager._curated_tools_controller = controller
    return controller


class ScannerStorageDialog(QDialog):
    """Modeless review of bounded metadata; file work remains on the controller."""

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._rows = []
        self._delete_prompt = None
        self._count_prompt = None
        self._page = 0
        self._page_current = False
        self._selection_identity = None
        self.setWindowTitle("Scanner retained reports · review and export")
        self.resize(820, 590)
        self.setModal(False)
        layout = QVBoxLayout(self)
        if hasattr(controller, "activities"):
            from angerona.gui.action_progress import ActionProgressView
            self.progress_view = ActionProgressView(controller.activities, self)
            layout.addWidget(self.progress_view)
        self.summary = _label("Loading retained scanner report metadata…")
        layout.addWidget(self.summary)
        layout.addWidget(_label("Unlimited removes the report slot limit. Storage bytes, free space and "
                                "managed file inventory still limit new reports. A finite count can allow one "
                                "extra report for the next scan. Export does not free storage. "
                                "Delete requires your explicit choice; changed or unresolved data stays held."))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(("Managed report", "State", "Recorded size"))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setMinimumWidth(0)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        layout.addWidget(self.table, 1)
        pages = QHBoxLayout()
        self.previous_page = QPushButton("Previous page")
        self.next_page = QPushButton("Next page")
        self.previous_page.clicked.connect(lambda: self._review_page(self._page - 1))
        self.next_page.clicked.connect(lambda: self._review_page(self._page + 1))
        pages.addWidget(self.previous_page)
        pages.addWidget(self.next_page)
        pages.addStretch(1)
        layout.addLayout(pages)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setUndoRedoEnabled(False)
        layout.addWidget(self.preview, 1)
        actions = QGridLayout()
        self.refresh_button = QPushButton("Refresh storage review")
        self.export_button = QPushButton("Export selected report…")
        self.delete_button = QPushButton("Delete selected report…")
        self.allow_report_button = QPushButton("Allow one extra report next scan…")
        close = QPushButton("Close · keep evidence")
        for index, button in enumerate((self.refresh_button, self.export_button, self.delete_button, self.allow_report_button, close)):
            actions.addWidget(button, index // 2, index % 2)
        layout.addLayout(actions)
        self.refresh_button.clicked.connect(lambda: self._review_page(self._page))
        self.export_button.clicked.connect(self._export)
        self.delete_button.clicked.connect(self._confirm_delete)
        self.allow_report_button.clicked.connect(self._confirm_extra_report)
        close.clicked.connect(self.close)
        controller.status_changed.connect(self._apply)
        from angerona.gui.window_controls import configure_work_window
        from angerona.gui.window_fit import install_window_fit
        configure_work_window(self)
        install_window_fit(self, scroll_content=True)
        self._apply(controller.snapshot())

    def _selected(self):
        index = self.table.currentRow()
        return self._rows[index] if 0 <= index < len(self._rows) else None

    def _review_page(self, page):
        if page == 0:
            self.controller.review_reports()
        elif page > 0:
            self.controller.review_reports(page=page)

    def _apply(self, snapshot):
        storage = snapshot.get("storage")
        storage = storage if type(storage) is dict else {}
        page, page_count = storage.get("page"), storage.get("page_count")
        paged = type(page) is int and type(page_count) is int and 0 <= page < page_count
        rows = snapshot.get("storage_reports")
        current = paged and type(rows) is list and not snapshot.get("storage_review_error")
        self._page_current = current and not snapshot.get("busy")
        rows = [row for row in rows[:_REPORT_REVIEW_PAGE_SIZE] if type(row) is dict] if current else []
        if rows != self._rows:
            selected = self._selected()
            if selected:
                self._selection_identity = selected.get("job_id")
            self._rows = copy.deepcopy(rows)
            self.table.blockSignals(True)
            self.table.setRowCount(len(self._rows))
            for index, row in enumerate(self._rows):
                size = row.get("bytes")
                cells = (row.get("job_id", "unknown"), row.get("state", "unknown"),
                         f"{size / 1024**2:.2f} MiB" if type(size) is int and size >= 0 else "unknown")
                for column, value in enumerate(cells):
                    item = QTableWidgetItem(_literal(value, 256))
                    item.setToolTip(_literal(value, 256))
                    self.table.setItem(index, column, item)
            chosen = next((index for index, row in enumerate(self._rows)
                           if row.get("job_id") == self._selection_identity), 0)
            if self._rows:
                self.table.selectRow(chosen)
            self.table.blockSignals(False)
        count, limit = storage.get("retained_reports"), storage.get("report_limit")
        facts = "Storage counts unavailable until review"
        if type(count) is int:
            if limit == SCANNER_REPORT_COUNT_UNLIMITED:
                facts = f"{count} retained report sets · Unlimited slots"
            elif type(limit) is int:
                facts = f"{count}/{limit} retained report sets"
        if current:
            self._page = page
            facts += f" · page {page + 1}/{page_count}"
        ready = self._page_current
        self.previous_page.setEnabled(ready and page > 0)
        self.next_page.setEnabled(ready and page + 1 < page_count)
        pending = snapshot.get("next_report_count_limit")
        if type(pending) is int:
            facts += f"; next scan only: up to {pending}"
        self.summary.setText(facts + "\n" + _literal(snapshot.get("message", ""), 1200))
        if storage.get("inventory_gap"):
            self.summary.setText(self.summary.text() + "\nAggregate storage tally unavailable: "
                                 + _literal(storage["inventory_gap"], 700))
        if snapshot.get("storage_review_error"):
            self.summary.setText(self.summary.text() + "\nStorage refresh unavailable: "
                                 + _literal(snapshot["storage_review_error"], 700))
        self.refresh_button.setEnabled(not snapshot.get("busy"))
        self.allow_report_button.setEnabled(not snapshot.get("busy") and _extra_report_choice(snapshot) is not None)
        self._selection_changed()

    def _selection_changed(self):
        row = self._selected()
        self.export_button.setEnabled(self._action_row("can_export") is not None)
        self.delete_button.setEnabled(self._action_row("can_delete") is not None)
        if row is not None:
            omitted = row.get("preview_omitted_characters", 0)
            suffix = f"\n\nPreview omits {omitted} characters; export retains the complete recorded files." if omitted else ""
            _set_document_text(self.preview, _literal(row.get("message", ""), 700) + "\n\n" + str(row.get("preview", "")) + suffix)
        else:
            self.preview.clear()

    def _action_row(self, permission):
        row = self._selected()
        if self._page_current and row is not None and row.get(permission) is True:
            return row
        return None

    def _export(self):
        row = self._action_row("can_export")
        if row is None:
            return
        destination = QFileDialog.getExistingDirectory(self, "Choose export destination; a fresh private folder will be created")
        if destination and row == self._action_row("can_export"):
            self.controller.export_report(job_id=row["job_id"], expected_receipt=row["receipt_sha256"], destination=destination)

    def _confirm_extra_report(self):
        snapshot = self.controller.snapshot()
        choice = _extra_report_choice(snapshot)
        if snapshot.get("busy") or choice is None or self._count_prompt is not None:
            return
        count, limit = choice
        prompt = self._count_prompt = QMessageBox(QMessageBox.Icon.Warning, "Allow one extra scanner report",
            f"Keep all {count} existing report sets and allow a maximum of {limit} for the next scan attempt?\n"
            "This does not start a scan or save settings. Byte, free-space and evidence checks still apply.\n"
            "The normal count applies again afterward.", parent=self)
        prompt.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        prompt.setDefaultButton(QMessageBox.StandardButton.No)
        prompt.setEscapeButton(QMessageBox.StandardButton.No)
        prompt.setWindowModality(Qt.WindowModality.NonModal)

        def answered(answer):
            self._count_prompt = None
            if answer == QMessageBox.StandardButton.Yes:
                self.controller.allow_next_report(retained_reports=count, accepted=True)
            prompt.deleteLater()

        prompt.finished.connect(answered)
        prompt.show()

    def _confirm_delete(self):
        row = self._action_row("can_delete")
        if row is None or self._delete_prompt is not None:
            return
        page = self._page
        expected = {row["job_id"]: row["receipt_sha256"]}
        prompt = self._delete_prompt = QMessageBox(QMessageBox.Icon.Warning, "Delete selected scanner report",
            "Delete this selected unchanged report set and its managed working data?\n" + row["job_id"] +
            "\nExport first if you need a copy. Unknown or changed files are preserved.", parent=self)
        prompt.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        prompt.setDefaultButton(QMessageBox.StandardButton.No)
        prompt.setWindowModality(Qt.WindowModality.NonModal)

        def answered(answer):
            self._delete_prompt = None
            if answer == QMessageBox.StandardButton.Yes and page == self._page and row == self._action_row("can_delete"):
                self.controller.clear_reports(expected, page=page)
            prompt.deleteLater()

        prompt.finished.connect(answered)
        prompt.show()

    def closeEvent(self, event):  # noqa: N802
        for attribute in ("_delete_prompt", "_count_prompt"):
            prompt = getattr(self, attribute)
            setattr(self, attribute, None)
            if prompt is not None and isValid(prompt):
                prompt.done(QMessageBox.StandardButton.No)
        super().closeEvent(event)


class CuratedToolsSettings(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._settings_save_pending = False
        cfg = _config(controller.manager)
        layout = QVBoxLayout(self)
        if hasattr(controller, "activities"):
            from angerona.gui.action_progress import ActionProgressView
            self.progress_view = ActionProgressView(controller.activities, self, config=cfg)
            layout.addWidget(self.progress_view)
        layout.addWidget(_label("Scanner setup runs after the dashboard paints. Scans follow the saved schedule or an explicit scan action."))
        self.controls = {}
        for name, (title, default) in _SETTINGS.items():
            if name in _COMMUNITY_SETTINGS:
                continue
            check = QCheckBox(title)
            check.setChecked(bool(getattr(cfg, name, default)))
            self.controls[name] = check
            layout.addWidget(check)
        community = QGroupBox("Community rules and playbooks")
        community_layout = QVBoxLayout(community)
        for name, (title, default) in _COMMUNITY_SETTINGS.items():
            check = QCheckBox(title)
            check.setObjectName(name)
            check.setChecked(getattr(cfg, name, default) is True)
            self.controls[name] = check
            community_layout.addWidget(check)
            warning = ("Only individually activated, validated rules are included. Imported matches do not grant response authority. "
                       "Invalid or unavailable packs leave bundled scanning available and report a coverage gap."
                       if name == "community_rules_enabled" else
                       "Only individually activated playbooks run. Containment requests still need verified original evidence, "
                       "existing response permissions, exact target identity and corroboration. This switch grants no administrator rights.")
            community_layout.addWidget(_label(warning))
        layout.addWidget(community)
        limits = QFormLayout()
        for name, (title, default, low, high) in _LIMITS.items():
            spin = QSpinBox()
            spin.setRange(low, high)
            spin.setValue(int(getattr(cfg, name, default)))
            self.controls[name] = spin
            limits.addRow(title, spin)
        self.report_count = QSpinBox()
        self.report_count.setRange(0, SCANNER_REPORT_COUNT_MAX)
        self.report_count.setSpecialValueText("Unlimited")
        count = scanner_report_count(getattr(cfg, "github_tools_report_count", SCANNER_REPORT_COUNT_UNLIMITED))
        self.report_count.setValue(0 if count == SCANNER_REPORT_COUNT_UNLIMITED else count)
        self.report_count.setToolTip("Unlimited removes the count policy. Byte, free-space and inventory checks still apply.")
        limits.addRow("Retained report slots", self.report_count)
        layout.addLayout(limits)
        self.priority = QComboBox()
        for title, value in (("Above normal", "above-normal"), ("High", "high")):
            self.priority.addItem(title, value)
        selected = self.priority.findData(getattr(cfg, "spyware_scan_priority", "above-normal"))
        self.priority.setCurrentIndex(max(0, selected))
        limits.addRow("Spyware Scan priority", self.priority)
        save = QPushButton("Save tool settings")
        self.save_button = save
        save.clicked.connect(self._save)
        layout.addWidget(save, 0, Qt.AlignmentFlag.AlignLeft)
        self.save_status = _label("Changes apply only after Save succeeds. Per-item activation remains separate.")
        self.save_status.setObjectName("CommunityRuntimeSettingsSaveStatus")
        layout.addWidget(self.save_status)
        clear = QPushButton("Delete scanner reports…")
        self.clear_reports_button = clear
        clear.clicked.connect(self._clear_reports)
        layout.addWidget(clear, 0, Qt.AlignmentFlag.AlignLeft)
        review = QPushButton("Review / export retained reports…")
        review.clicked.connect(controller.show_storage_review)
        layout.addWidget(review, 0, Qt.AlignmentFlag.AlignLeft)
        self.controller.status_changed.connect(self._update_busy)
        layout.addWidget(_label("Advanced standalone phone checks use a private password prompt. "
                                "Optional pattern, backup and acquisition components need their own reviewed runtime."))
        layout.addStretch(1)
        self._update_busy(self.controller.snapshot())

    def _update_busy(self, snapshot):
        self.save_button.setEnabled(not snapshot.get("busy"))
        self.clear_reports_button.setEnabled(not snapshot.get("busy"))
        if (self._settings_save_pending and not snapshot.get("busy")
                and snapshot.get("active_action") == "settings" and snapshot.get("lifecycle") == "terminal"):
            self._settings_save_pending = False
            cfg = _config(self.controller.manager)
            for name, (_title, default) in _COMMUNITY_SETTINGS.items():
                self.controls[name].setChecked(getattr(cfg, name, default) is True)
            failed = snapshot.get("state") in {"failed", "cancelled", "timed-out"}
            self.save_status.setText(("Save failed; community runtime switches retain their saved values. "
                                      + str(snapshot.get("error", snapshot.get("message", "")))[:500]) if failed else
                                     "Tool settings saved. Only individually activated community data can run; response permissions are unchanged.")

    def _save(self):
        values = {name: widget.isChecked() if name in _SETTINGS else widget.value()
                  for name, widget in self.controls.items()}
        count = self.report_count.value()
        values["github_tools_report_count"] = SCANNER_REPORT_COUNT_UNLIMITED if count == 0 else count
        values["spyware_scan_priority"] = self.priority.currentData()
        if self.controller.save_options(values):
            self._settings_save_pending = True
            self.save_status.setText("Saving in background; current runtime switches remain unchanged until persistence succeeds.")

    def _clear_reports(self):
        if QMessageBox.question(self, "Delete scanner reports",
                                "Delete all unchanged reports and working data from completed managed scanner jobs? "
                                "For collections larger than 32, select individual reports in storage review. "
                                "Unknown or modified files, preferences and source-library imports are preserved.",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.controller.clear_reports()


class ClickChoice(QComboBox):
    """Keep a parent scroll gesture from silently changing a scan choice."""

    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


class ClickNumber(QSpinBox):
    def wheelEvent(self, event):  # noqa: N802
        event.ignore()


def style_spyware_scan_button(button):
    button.setStyleSheet(
        "QPushButton { background:#b91c1c; color:#fff1f2; border:1px solid #ef4444; "
        "border-radius:6px; padding:7px 14px; font-weight:800; }"
        "QPushButton:hover { background:#dc2626; }"
        "QPushButton:disabled { background:#442126; color:#b9a3a6; }"
    )


class ScanProgressRing(ProgressRing):
    """Compatible Spyware Scan surface for the shared measured workflow ring."""

    def __init__(self, config, parent=None):
        super().__init__(config, parent, scope="overall workflow")


def _measured(value, *, maximum=None):
    if type(value) not in (int, float) or value < 0:
        return None
    try:
        if not math.isfinite(value):
            return None
    except OverflowError:
        return None
    return min(value, maximum) if maximum is not None else value


def _resource_number(value, unit, divisor=1):
    value = _measured(value)
    return f"{value / divisor:,.1f}{unit}" if value is not None else "unavailable"


def _duration(value):
    seconds = _measured(value)
    if seconds is None:
        return "Calculating"
    seconds = int(seconds)
    return f"{seconds // 3600:d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}" if seconds >= 3600 else f"{seconds // 60:d}:{seconds % 60:02d}"


class ScanStepRow(QWidget):
    """Stable reader row: observations change, the widget and scroll do not."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 3, 4, 3)
        layout.setSpacing(2)
        self.caption = _label()
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.count = _label()
        layout.addWidget(self.caption)
        layout.addWidget(self.bar)
        layout.addWidget(self.count)

    def apply(self, source, step, *, terminal=False):
        state = _literal(step.get("state", "pending"), 32)
        display_state = ("Not run" if terminal and state in {"pending", "queued"} else
                         "Interrupted" if terminal and state in {"running", "cancelling"} else state)
        percent = None
        fractional_item = False
        # Derive reader completion from counted units. A current database
        # query/file fraction is not a fraction of an entire toolkit reader.
        completed, total = _measured(step.get("completed")), _measured(step.get("total"))
        if total is not None and total > 0 and completed is not None and completed <= total:
            percent = completed * 100 / total
            if (source == "Native SpywareGuard" and step.get("id") == "hashes"
                    and step.get("unit") == "candidate records"
                    and step.get("percent_basis") == "completed candidate slots plus current file byte fraction"
                    and state in {"running", "cancelling", "cancelled", "failed"}
                    and type(step.get("completed")) is int and type(step.get("total")) is int
                    and completed < total <= 4096 and step.get("item_unit") == "bytes"
                    and type(step.get("item_completed")) is int and type(step.get("item_total")) is int
                    and 0 <= step["item_completed"] <= step["item_total"] <= 16 * 1024**2
                    and step["item_total"] > 0):
                percent = (completed + step["item_completed"] / step["item_total"]) * 100 / total
                fractional_item = True
        if state in {"running", "queued", "cancelling", "pending"} and percent is not None:
            percent = min(percent, 99)
        self.caption.setText(f"{source} · {_literal(step.get('label', step.get('id', 'Check')), 120)} · {display_state}")
        _set_progress(self.bar, int(percent) if percent is not None else 0,
                      (f"{percent:.1f}%" if fractional_item else f"{percent:.0f}%")
                      if percent is not None else "Indeterminate · no known total")
        accessible = self.caption.text() + ": " + self.bar.format()
        if self.bar.accessibleName() != accessible:
            self.bar.setAccessibleName(accessible)
        unit = _literal(step.get('unit', 'items'), 40)
        checked, skipped = _measured(step.get("checked")), _measured(step.get("skipped"))
        unknown_checked = total is None and completed == 0 and unit == "checks" and checked is not None
        count = (f"checked {checked:,.0f} · total unknown" if unknown_checked
                 else f"{completed:,.0f}/{total:,.0f} {unit}" if completed is not None and total is not None
                 else f"{completed:,.0f} {unit} processed · total unknown" if completed is not None
                 else "Total not yet known")
        if checked is not None and not unknown_checked:
            count += f" · checked {checked:,.0f}"
        if skipped is not None:
            count += f" · skipped {skipped:,.0f}"
        item_done, item_total = _measured(step.get("item_completed")), _measured(step.get("item_total"))
        step_ended = terminal or state in {"completed", "cancelled", "failed", "skipped", "disabled"}
        if item_done is not None and item_total and item_done <= item_total:
            count += f"\nCurrent item: {item_done:,.0f}/{item_total:,.0f} {_literal(step.get('item_unit', 'bytes'), 24)} ({item_done * 100 / item_total:.0f}%)"
            count += " · item ETA " + ("— (step ended)" if step_ended else _duration(step.get('item_remaining_s')))
            if fractional_item:
                count += " · step includes this current-file byte fraction"
        eta = "— (step ended)" if step_ended else _duration(step.get("remaining_s"))
        elapsed = _duration(step.get("elapsed_s")) if _measured(step.get("elapsed_s")) is not None else "unavailable"
        self.count.setText(count + f" · elapsed {elapsed} · ETA {eta}")


class SpywareScanControls(QWidget):
    """Readable request scope, included checks and copied workflow observations."""

    def __init__(self, manager, parent=None, *, controller=None, scope_controls=True):
        super().__init__(parent)
        self.controller = controller or get_curated_tools_controller(manager)
        self._has_scope_controls = scope_controls
        cfg = _config(manager)
        self._scope_mode = "full"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.setup_body = QWidget()
        self._section_grid = QGridLayout(self.setup_body)
        self._section_grid.setContentsMargins(0, 0, 0, 0)
        self.scope_group = QGroupBox("Scope", self.setup_body)
        scope = QVBoxLayout(self.scope_group)
        self.scope_button = _ScanToolButton()
        self.scope_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.scope_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.scope_button.setAccessibleName("Change spyware scan scope")
        menu = QMenu(self.scope_button)
        self._scope_actions = {}
        group = QActionGroup(menu)
        group.setExclusive(True)
        for title, mode in (("Entire PC · supported full checks", "full"),
                            ("Browser checks", "browser"), ("Standard system checks", "default"),
                            ("Selected local evidence", "targeted")):
            action = menu.addAction(title)
            action.setCheckable(True)
            action.setChecked(mode == "full")
            group.addAction(action)
            action.triggered.connect(lambda _checked=False, value=mode: self._set_scope(value))
            self._scope_actions[mode] = action
        self.scope_button.setMenu(menu)
        scope.addWidget(self.scope_button)
        self.scope_description = _label()
        scope.addWidget(self.scope_description)
        self.scope_paths = QPlainTextEdit()
        self.scope_paths.setPlaceholderText("Selected local paths, one per line")
        self.scope_paths.setMaximumHeight(64)
        self.scope_paths.document().setMaximumBlockCount(16)
        self.scope_choose = QPushButton("Choose evidence folder…")
        self.scope_choose.clicked.connect(self._choose_scope_folder)
        scope.addWidget(self.scope_paths)
        scope.addWidget(self.scope_choose)
        self.scope_error = _label()
        scope.addWidget(self.scope_error)
        self._set_scope("full")
        self.scope_group.setVisible(scope_controls)

        self.checks_group = QGroupBox("Included checks", self.setup_body)
        checks = QVBoxLayout(self.checks_group)
        self.native = QCheckBox("Native SpywareGuard")
        self.native.setChecked(bool(getattr(cfg, "spyware_scan_native_enabled", True)))
        self.zero_breach = QCheckBox("Zero-Breach Toolkit")
        self.zero_breach.setChecked(bool(getattr(cfg, "spyware_scan_zero_breach_enabled", True)))
        checks.addWidget(self.native)
        checks.addWidget(self.zero_breach)
        self.toggle = _ScanToolButton()
        self.toggle.setText("Priority and resource limits")
        self.toggle.setCheckable(True)
        self.toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        checks.addWidget(self.toggle)
        self.options = QWidget()
        form = QFormLayout(self.options)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.priority = ClickChoice()
        for title, value in (("Above normal", "above-normal"), ("High", "high")):
            self.priority.addItem(title, value)
        self.priority.setCurrentIndex(max(0, self.priority.findData(getattr(cfg, "spyware_scan_priority", "above-normal"))))
        form.addRow("Priority", self.priority)
        self.cpu = ClickNumber()
        self.cpu.setRange(10, 90)
        self.cpu.setValue(int(getattr(cfg, "spyware_scan_cpu_percent", 70)))
        form.addRow("CPU ceiling (%)", self.cpu)
        self.memory = ClickNumber()
        self.memory.setRange(128, 2048)
        self.memory.setValue(int(getattr(cfg, "spyware_scan_memory_mib", 512)))
        form.addRow("Memory ceiling (MiB)", self.memory)
        self.budget = ClickNumber()
        self.budget.setRange(30, 14400)
        self.budget.setValue(int(getattr(cfg, "spyware_scan_timeout_seconds", 3600)))
        self.budget.setSuffix(" s")
        self.budget.setToolTip("Per-run Spyware Scan budget only. Starts from its saved default; never saves preferences or extends an active scan. Standalone Run scan uses the separate toolkit deadline.")
        checks.addWidget(_label("Spyware Scan budget for the next run"))
        checks.addWidget(self.budget)
        checks.addWidget(_label("A scan that reaches this budget keeps its partial results."))
        self.options.hide()
        self.toggle.toggled.connect(self.options.setVisible)
        self.toggle.toggled.connect(lambda opened: self.toggle.setArrowType(
            Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow))
        checks.addWidget(self.options)
        schedule = QGroupBox("Automatic scan")
        schedule_form = QFormLayout(schedule)
        schedule_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.auto_scan_enabled = QCheckBox("Run once a day")
        self.auto_scan_enabled.setChecked(getattr(cfg, "spyware_scan_auto_enabled", True) is True)
        self.auto_scan_scope = QComboBox()
        for label, scope in (("Entire PC", "full"), ("Browser checks", "browser"), ("Quick system checks", "quick")):
            self.auto_scan_scope.addItem(label, scope)
        self.auto_scan_scope.setCurrentIndex(max(0, self.auto_scan_scope.findData(
            getattr(cfg, "spyware_scan_auto_scope", "full"))))
        self.auto_scan_save = QPushButton("Save automatic scan settings")
        self.auto_scan_save.clicked.connect(lambda: self.controller.save_options({
            "spyware_scan_auto_enabled": self.auto_scan_enabled.isChecked(),
            "spyware_scan_auto_scope": self.auto_scan_scope.currentData(),
        }))
        schedule_form.addRow(self.auto_scan_enabled)
        schedule_form.addRow("Scope", self.auto_scan_scope)
        schedule_form.addRow(self.auto_scan_save)
        checks.addWidget(schedule)
        schedule.setVisible(scope_controls)
        self._section_grid.addWidget(self.scope_group, 0, 0)
        self._section_grid.addWidget(self.checks_group, 0, 1 if scope_controls else 0)

        self.progress_group = QGroupBox("Progress")
        self._progress_grid = QGridLayout(self.progress_group)
        self.progress_ring = ScanProgressRing(cfg)
        self._progress_captions = QWidget()
        captions = QVBoxLayout(self._progress_captions)
        captions.setContentsMargins(0, 0, 0, 0)
        self.progress_stage = _label("Ready for an explicit scan request.")
        self.progress_stage.setStyleSheet("font-weight:700;")
        self.progress_count = _label("No workflow is running.")
        captions.addWidget(self.progress_stage)
        captions.addWidget(self.progress_count)
        self.progress_count.setToolTip("Overall weights workflow stages equally. Reader percentages use counted records or bytes. "
                                       "Unknown totals stay indeterminate. These figures describe measured work.")
        self.scanner_summaries = {"native": _label(), "toolkit": _label()}
        for label in self.scanner_summaries.values():
            captions.addWidget(label)
        self.cancel_button = QPushButton("Stop scan")
        self.cancel_button.clicked.connect(self.controller.cancel)
        self._progress_grid.addWidget(self.progress_ring, 0, 0)
        self._progress_grid.addWidget(self._progress_captions, 0, 1)
        self._progress_grid.addWidget(self.cancel_button, 0, 2)
        self._progress_grid.setColumnStretch(1, 1)
        layout.addWidget(self.progress_group)
        self.activity = _ScanObservedText("task", "Current task: waiting for an explicit scan request.")
        self.current_file = _ScanObservedText("file", "Current file: not supplied.")
        self.item_caption = _label()
        self.item_progress = QProgressBar()
        self.item_progress.setRange(0, 100)
        self.item_progress.setToolTip("Only the current observed file/query item. This is separate from reader completion and overall workflow progress.")
        self.timing = _label()
        self.hits = _label("Hits · Run a scan to see what it found.")
        self.hits.setStyleSheet("font-weight:600;")
        self.review_notice = _label()
        self.review_button = _ScanToolButton()
        self.review_button.setText("Open After-action")
        self.review_button.clicked.connect(self._open_report)
        self.outcome = _label()
        self.outcome.setStyleSheet("color:#fbbf24;font-weight:600;")
        for label in (self.hits, self.outcome, self.review_notice):
            layout.addWidget(label)
        layout.addWidget(self.review_button, 0, Qt.AlignmentFlag.AlignLeft)

        self.setup_toggle = _ScanToolButton()
        self.setup_toggle.setText("Scan setup")
        self.setup_toggle.setCheckable(True)
        self.setup_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.setup_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.setup_toggle.toggled.connect(self._set_setup_open)
        self.setup_summary = _label()
        self.native.toggled.connect(self._update_setup_summary)
        self.zero_breach.toggled.connect(self._update_setup_summary)
        self.budget.valueChanged.connect(self._update_setup_summary)
        self._update_setup_summary()
        self.setup_body.hide()
        layout.addWidget(self.setup_toggle, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.setup_summary)
        layout.addWidget(self.setup_body)

        self.step_toggle = _ScanToolButton()
        self.step_toggle.setText("Per-check and reader progress")
        self.step_toggle.setCheckable(True)
        self.step_toggle.setChecked(True)
        self.step_toggle.setArrowType(Qt.ArrowType.DownArrow)
        self.step_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        step_actions = QHBoxLayout()
        step_actions.addWidget(self.step_toggle, 1)
        self.storage_button = QPushButton("Review scanner storage…")
        self.storage_button.clicked.connect(lambda: getattr(self.controller, "show_storage_review", lambda: None)())
        step_actions.addWidget(self.storage_button)
        layout.addLayout(step_actions)
        self.steps_scroll = QScrollArea()
        self.steps_scroll.setWidgetResizable(True)
        self.steps_scroll.setMinimumHeight(90)
        self.steps_scroll.setMaximumHeight(220)
        self.steps_body = QWidget()
        self.steps_layout = QVBoxLayout(self.steps_body)
        self.steps_layout.setContentsMargins(0, 0, 0, 0)
        self.steps_layout.addStretch(1)
        self.steps_scroll.setWidget(self.steps_body)
        self.step_rows = {}
        self.step_toggle.toggled.connect(self.steps_scroll.setVisible)
        self.step_toggle.toggled.connect(lambda opened: self.step_toggle.setArrowType(
            Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow))
        layout.addWidget(self.steps_scroll)

        self.explanation_group = QGroupBox("What's happening now")
        explanation = QVBoxLayout(self.explanation_group)
        self.stage_explanation = _label()
        explanation.addWidget(self.stage_explanation)
        for observation in (self.activity, self.current_file, self.timing, self.item_caption, self.item_progress):
            explanation.addWidget(observation)
        self._stage_grid = QGridLayout()
        self.stage_chips = {}
        for stage, title in (("preflight", "Preflight"), ("native", "Native"),
                             ("toolkit", "Toolkit"), ("aggregation", "Report")):
            chip = _label(title)
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setToolTip("A finished workflow stage is not a clean-host verdict.")
            self.stage_chips[stage] = chip
            self._stage_grid.addWidget(chip, 0, len(self.stage_chips) - 1)
        explanation.addLayout(self._stage_grid)
        self.explanation_toggle = _ScanToolButton()
        self.explanation_toggle.setText("Coverage and technical details")
        self.explanation_toggle.setCheckable(True)
        self.explanation_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.explanation_toggle.setArrowType(Qt.ArrowType.RightArrow)
        explanation.addWidget(self.explanation_toggle)
        self.explanation_details = _label(
            "Native SpywareGuard checks its supported live system sources; its thread's resource "
            "totals are not separately measured here. Zero-Breach runs "
            "separate supported checks in an owned ordinary-user process. A scope selection "
            "changes toolkit checks; native live checks retain their supported system scope.\n\n"
            "Full mode does not read or verify every file. Missing collectors, permissions and "
            "incomplete checks stay explicit. Privilege verification observes the current token; "
            "it does not elevate the app.\n\n"
            "Hit: an observation or match to review. External toolkit findings remain leads. "
            "A contextual reference adds background. A withdrawn indicator is historical. "
            "Coverage gaps are checks that were skipped, unavailable, or interrupted. "
            "A clean verdict requires more evidence than a finished workflow.\n\n"
            "ETA: estimated time remaining from measured work. The time budget is the selected "
            "scan limit. Owned work may take longer to stop safely. The report opens after the "
            "selected work settles. Response requires validated evidence, a target and authority."
        )
        self.explanation_details.hide()
        self.explanation_toggle.toggled.connect(self.explanation_details.setVisible)
        self.explanation_toggle.toggled.connect(lambda opened: self.explanation_toggle.setArrowType(
            Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow))
        explanation.addWidget(self.explanation_details)

        self.resource_group = QGroupBox("Computer specs" if scope_controls
                                       else "Scan resources & permissions")
        resources = QVBoxLayout(self.resource_group)
        self.host_specs = _label("Host sample unavailable.") if scope_controls else None
        if self.host_specs is not None:
            self.host_specs.setToolTip("Latest available System Pulse sample for the whole computer.")
            resources.addWidget(self.host_specs)
        self.resources = _label()
        self.privileges = _label()
        resources.addWidget(self.resources)
        resources.addWidget(self.privileges)
        self.privileges.setToolTip("Current-token observations do not grant administrator rights or response authority.")
        next_section = layout.indexOf(self.review_button) + 1
        layout.insertWidget(next_section, self.explanation_group)
        layout.insertWidget(next_section + 1, self.resource_group)
        for section, role in ((self.progress_group, "monitor"), (self.explanation_group, "analysis"),
                              (self.resource_group, "monitor"), (self.scope_group, "configure"),
                              (self.checks_group, "configure")):
            set_function_role(section, role)
            section.layout().setContentsMargins(8, 6, 8, 6)
            section.layout().setSpacing(4)
        for control, role in ((self.cancel_button, "response"), (self.review_button, "analysis"),
                              (self.setup_toggle, "configure"), (self.step_toggle, "monitor"),
                              (self.storage_button, "configure"), (self.explanation_toggle, "analysis")):
            set_function_role(control, role)
        initial = self.controller.snapshot()
        self._apply(initial)
        self._presentation = _ScanViewPresentation(self, initial)
        self.controller.status_changed.connect(self._presentation.receive)
        self._clock = PresentationTimer(self, pressure_sensitive=False, chill_sensitive=False)
        self._clock.setInterval(1000)
        self._clock.timeout.connect(self._tick_elapsed)
        self._clock.start()

    @Slot(object)
    def update_computer_specs(self, sample):
        if self.host_specs is None or type(sample) is not dict or not sample or sample.get("error"):
            return
        cpu = _resource_number(sample.get("cpu"), "%")
        memory = _resource_number(sample.get("ram"), "%")
        total = _resource_number(sample.get("memory_total"), " GiB", 1024**3)
        available = _resource_number(sample.get("available"), " GiB", 1024**3)
        text = f"Host CPU load: {cpu}\nHost memory: {total} total · {available} available · {memory} used"
        if self.host_specs.text() != text:
            self.host_specs.setText(text)

    def _tick_elapsed(self):
        if self._presentation.visible():
            snapshot = self._presentation.latest
            if snapshot.get("busy"):
                self._apply_timing(snapshot, getattr(self, "_timing_current", None))

    def _apply_timing(self, snapshot, current=None):
        current = current if type(current) is dict else {}
        readers = snapshot.get("scanner_progress")
        unbound_ready = (
            self._has_scope_controls and snapshot.get("busy") is False
            and snapshot.get("state") in ("ready", "idle")
            and snapshot.get("lifecycle") in (None, "idle", "terminal")
            and snapshot.get("active_action") not in ("scan", "priority_scan")
            and snapshot.get("scan_progress") is None
            and (readers is None or type(readers) is dict and not readers)
            and not current
            and all(snapshot.get(key) is None for key in (
                "request_id", "native_scan_completion", "partial_result",
                "storage_hold", "job_id", "report", "review_gap", "previous_attempt"))
            and (snapshot.get("review_available") is None or snapshot.get("review_available") is False)
        )
        if unbound_ready:
            budget = self.budget.value()
            self.timing.setText(f"Ready · next Spyware Scan budget {_duration(budget)} ({budget}s)")
            self.timing.setToolTip("No current scan request is bound to this ready/idle view. "
                                   "This is the selected budget for the next Spyware Scan, not elapsed scan work. "
                                   "Retained reports and their coverage limits are unchanged.")
            return
        started = _measured(snapshot.get("started_monotonic"))
        elapsed = (max(0, time.monotonic() - started) if snapshot.get("busy") and started is not None
                   else snapshot.get("elapsed_seconds", current.get("elapsed_s")))
        budget = snapshot.get("timeout_seconds", self.budget.value())
        remaining = current.get("remaining_s")
        eta = _duration(remaining)
        basis = "measured estimate" if _measured(remaining) is not None else "insufficient measured work"
        if not snapshot.get("busy"):
            eta, basis = "—", "run ended" if snapshot.get("lifecycle") == "terminal" else "no active estimate"
        allowance = max(0, budget - elapsed) if type(budget) is int and _measured(elapsed) is not None else None
        deadline = f" · budget remaining {_duration(allowance)}" if snapshot.get("busy") else ""
        elapsed_text = _duration(elapsed) if _measured(elapsed) is not None else "unavailable"
        self.timing.setText(f"Elapsed {elapsed_text} · ETA {eta} ({basis}) · time budget {budget}s{deadline}")
        self.timing.setToolTip("ETA is a measured estimate when available; time budget is a deadline, not an estimate of scan duration.")

    def _set_scope(self, mode):
        self._scope_mode = mode
        titles = {"full": "Entire PC · change scope…", "browser": "Browser checks · change scope…",
                  "default": "Standard system checks · change scope…", "targeted": "Selected local evidence · change scope…"}
        self.scope_button.setText(titles[mode])
        self.scope_description.setText({
            "full": "Supported system-wide spyware checks; this does not verify every file.",
            "browser": "Supported browser artifacts from the selected scanners.",
            "default": "Standard system checks from the selected scanners.",
            "targeted": "Checks stay within the local evidence you select.",
        }[mode])
        self._scope_actions[mode].setChecked(True)
        self.scope_paths.setVisible(mode == "targeted")
        self.scope_choose.setVisible(mode == "targeted")
        self.scope_error.clear()
        self.scope_error.hide()
        if hasattr(self, "setup_summary"):
            self._update_setup_summary()

    def _update_setup_summary(self):
        names = {"full": "Entire PC", "browser": "Browser checks", "default": "Standard checks",
                 "targeted": "Selected evidence"}
        selected = [name for name, control in (("Native SpywareGuard", self.native), ("Zero-Breach", self.zero_breach))
                    if control.isChecked()]
        scope = f"{names[self._scope_mode]} · " if self._has_scope_controls else ""
        checks = " + ".join(selected) if selected else "No checks selected"
        self.setup_summary.setText(f"{scope}{checks} · next run {_duration(self.budget.value())}")
        presentation = getattr(self, "_presentation", None)
        if presentation is not None:
            self._apply_timing(presentation.latest, getattr(self, "_timing_current", None))

    def _set_setup_open(self, opened):
        self.setup_body.setVisible(opened)
        self.setup_toggle.setArrowType(Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow)
        if opened:
            self._reflow_scan()

    def _open_report(self):
        opener = getattr(self.controller, "open_retained_scan_report", None)
        if callable(opener):
            opener()

    def _choose_scope_folder(self):
        selected = QFileDialog.getExistingDirectory(self, "Choose local spyware evidence")
        if selected:
            lines = self.scope_paths.toPlainText().splitlines()
            self.scope_paths.setPlainText("\n".join((*lines, selected)[-16:]))

    def start(self, **options):
        selected = dict(mode=self._scope_mode,
                        targets=tuple(line.strip() for line in self.scope_paths.toPlainText().splitlines() if line.strip())[:16]
                        if self._scope_mode == "targeted" else ())
        selected.update(options)
        selected.setdefault("timeout_seconds", self.budget.value())
        if selected["mode"] == "targeted" and not selected.get("targets"):
            self.setup_toggle.setChecked(True)
            self.scope_error.setText("Choose local evidence before starting this scope.")
            self.scope_error.show()
            return False
        return self.controller.priority_scan(native_enabled=self.native.isChecked(),
                                             zero_breach_enabled=self.zero_breach.isChecked(),
                                             priority=self.priority.currentData(), max_cpu_percent=self.cpu.value(),
                                             max_memory_mib=self.memory.value(), **selected)

    @staticmethod
    def _content_width(owner, layout):
        margins = layout.contentsMargins()
        width = owner.contentsRect().width()
        parent = owner.parentWidget()
        if parent is not None:
            # A scroll area can hold us at the old two-column minimum while
            # its viewport has already shrunk. Fit the viewport before the
            # layout's current minimum can keep those columns locked in place.
            width = min(width, parent.contentsRect().width())
        return max(0, width - margins.left() - margins.right())

    def _reflow_scan(self):
        if not hasattr(self, "stage_chips") or getattr(self, "_reflowing_scan", False):
            return
        self._reflowing_scan = True
        try:
            for widget in (self.scope_group, self.checks_group, self.cancel_button, *self.stage_chips.values()):
                widget.ensurePolished()
            self.progress_ring.ensurePolished()
            self.progress_ring._fit_font()
            spacing = max(0, self._section_grid.horizontalSpacing())
            section_width = self._content_width(self, self.layout())
            # Layout minima include the actual polished controls and font metrics.
            needed = (self.scope_group.minimumSizeHint().width()
                      + self.checks_group.minimumSizeHint().width() + spacing)
            stacked = not self._has_scope_controls or section_width < needed
            if stacked != getattr(self, "_sections_stacked", None):
                self._sections_stacked = stacked
                self._section_grid.removeWidget(self.checks_group)
                self._section_grid.addWidget(self.checks_group, 1 if stacked else 0, 0 if stacked else 1)
                self._section_grid.setColumnStretch(0, 1)
                self._section_grid.setColumnStretch(1, 0 if stacked else 1)

            available = self._content_width(self.progress_group, self._progress_grid)
            gap = max(0, self._progress_grid.horizontalSpacing())
            ring = self.progress_ring.minimumSizeHint().expandedTo(self.progress_ring.minimumSize()).width()
            stop = self.cancel_button.minimumSizeHint().width()
            # A caption column must have readable line lengths, not just a zero
            # horizontal minimum for a wrapping label.
            caption = self._progress_captions.fontMetrics().averageCharWidth() * 36
            progress_mode = 0 if available >= ring + stop + caption + gap * 2 else (
                1 if available >= ring + stop + gap else 2)
            if progress_mode != getattr(self, "_progress_mode", None):
                self._progress_mode = progress_mode
                for widget in (self.progress_ring, self._progress_captions, self.cancel_button):
                    self._progress_grid.removeWidget(widget)
                for column in range(3):
                    self._progress_grid.setColumnStretch(column, 0)
                if progress_mode == 0:
                    self._progress_grid.addWidget(self.progress_ring, 0, 0)
                    self._progress_grid.addWidget(self._progress_captions, 0, 1)
                    self._progress_grid.addWidget(self.cancel_button, 0, 2)
                    self._progress_grid.setColumnStretch(1, 1)
                elif progress_mode == 1:
                    self._progress_grid.addWidget(self.progress_ring, 0, 0)
                    self._progress_grid.addWidget(self.cancel_button, 0, 1, alignment=Qt.AlignmentFlag.AlignRight)
                    self._progress_grid.addWidget(self._progress_captions, 1, 0, 1, 2)
                    self._progress_grid.setColumnStretch(1, 1)
                else:
                    self._progress_grid.addWidget(self.progress_ring, 0, 0, alignment=Qt.AlignmentFlag.AlignHCenter)
                    self._progress_grid.addWidget(self._progress_captions, 1, 0)
                    self._progress_grid.addWidget(self.cancel_button, 2, 0)
                    self._progress_grid.setColumnStretch(0, 1)

            available = self._content_width(self.explanation_group, self.explanation_group.layout())
            gap = max(0, self._stage_grid.horizontalSpacing())
            chips = tuple(self.stage_chips.values())
            widths = [chip.sizeHint().width() for chip in chips]
            columns = 1
            for count in range(len(chips), 0, -1):
                if (sum(max(widths[column::count]) for column in range(count))
                        + gap * (count - 1) <= available):
                    columns = count
                    break
            if columns != getattr(self, "_stage_columns", None):
                self._stage_columns = columns
                for chip in chips:
                    self._stage_grid.removeWidget(chip)
                for column in range(len(chips)):
                    self._stage_grid.setColumnStretch(column, 1 if column < columns else 0)
                for index, chip in enumerate(chips):
                    self._stage_grid.addWidget(chip, index // columns, index % columns)
        finally:
            self._reflowing_scan = False

    def event(self, event):
        result = super().event(event)
        if event.type() in (QEvent.Type.LayoutRequest, QEvent.Type.FontChange, QEvent.Type.StyleChange):
            self._reflow_scan()
        return result

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        self._reflow_scan()

    def _apply(self, snapshot):
        busy = snapshot.get("busy") is True
        ended = not busy and snapshot.get("lifecycle") == "terminal"
        progress = snapshot.get("scan_progress")
        progress = progress if type(progress) is dict and progress.get("unit") == "workflow_stages" else {}
        finished, total = progress.get("finished"), progress.get("total")
        readers = snapshot.get("scanner_progress")
        readers = readers if type(readers) is dict else {}
        planned = progress.get("planned_stages")
        planned = planned if type(planned) in (tuple, list) else (("toolkit",) if "toolkit" in readers else ())
        self._apply_hits(snapshot, progress, planned)
        review_available = snapshot.get("review_available") is True
        review_gap = snapshot.get("review_gap")
        self.review_notice.setText(_literal(review_gap, 700) if review_gap else "After-action report ready for review.")
        _set_visible(self.review_notice, review_available)
        _set_visible(self.review_button, review_available)
        _set_enabled(self.review_button, review_available and not busy)
        done = progress.get("finished_stages")
        done = done if type(done) in (tuple, list) else ()
        native_reader = readers.get("native")
        # Reader work may settle while the orchestrator awaits the toolkit.
        # This changes presentation only; it does not finish a workflow stage.
        native_checks_finished = ("native" in planned and (ended or busy and "native" not in done)
                                  and type(native_reader) is dict
                                  and native_reader.get("state") == "completed")
        fractions = []
        for name in planned:
            if name in done or (name == "native" and native_checks_finished):
                fractions.append(1.0)
                continue
            source = readers.get(name)
            source = source if type(source) is dict else {}
            percent = _measured(source.get("overall_percent"), maximum=100)
            if percent is None:
                completed, count = _measured(source.get("completed_steps")), _measured(source.get("total_steps"))
                percent = completed * 100 / count if completed is not None and count and completed <= count else 0
            fractions.append(percent / 100)
        if fractions and readers:
            self.progress_ring.set_fraction(sum(fractions) / len(fractions), busy)
        else:
            self.progress_ring.set_state(finished, total, busy)
        labels = {"preflight": "Verifying available checks", "toolkit": "Running supported toolkit checks",
                  "native": "Waiting for native SpywareGuard", "aggregation": "Reviewing results and retiring owned work",
                  "cancelling": "Stopping owned scan work", "finished": "Workflow finished · review findings and coverage"}
        stage = labels.get(progress.get("stage"))
        if ended and snapshot.get("state") == "held":
            stage = "Scan held · review storage or coverage requirements"
        if progress.get("stage") == "finished" and snapshot.get("state") == "incomplete":
            stage = "Workflow finished · incomplete coverage"
        if not busy and snapshot.get("state") in {"failed", "timed-out", "cancelled"}:
            stage = {"failed": "Scan failed · partial progress retained", "timed-out": "Time budget reached · partial progress retained",
                     "cancelled": "Scan cancelled · partial progress retained"}[snapshot["state"]]
        elif snapshot.get("lifecycle") == "draining":
            stage = "Stopping · waiting for exact owned checks to retire"
        elif busy and stage:
            stage = "Running · " + stage
        self.progress_stage.setText(stage or ("Working · exact progress unavailable" if busy else
                                              f"Scan state: {_literal(snapshot.get('state', 'idle'), 60)}"))
        state = snapshot.get("state")
        color = ("#38bdf8" if busy else "#4ade80" if state == "completed" else
                 "#fb7185" if state in {"failed", "unavailable", "timed-out"} else
                 "#fbbf24" if state in {"held", "incomplete", "cancelled"} else "#cbd5e1")
        self.progress_stage.setStyleSheet(f"font-weight:700;color:{color};")
        explanations = {
            "preflight": "Checking which selected scanners and privileges are available. Next: run the supported checks.",
            "toolkit": "The toolkit is checking supported spyware traces. Its exact file completion is unavailable. Next: wait for remaining native work.",
            "native": "Waiting for this request's native SpywareGuard checks. Next: assemble findings and explicit coverage gaps.",
            "aggregation": "Selected work has settled; results and owned-work retirement are being reviewed. Next: publish the report.",
            "cancelling": "Cancellation has been requested. Next: wait for owned checks to stop and review any partial evidence.",
            "finished": "The scan ended. Review what it found and which checks it could complete.",
        }
        fallback = {
            "held": "The requested checks are held by current runtime or permission limits. Next: review coverage and the existing setup requirements.",
            "failed": "The request failed. Next: review its diagnostic report and partial coverage before trying again.",
            "unavailable": "A required scanner or status source is unavailable. Next: review setup and the reported coverage gap.",
            "cancelled": "The request was cancelled. Next: review any partial evidence; cancellation does not establish a clean PC.",
            "incomplete": "Some selected checks did not complete. Next: review the report's explicit coverage gaps and findings.",
        }.get(state, "Waiting for an explicit request or structured worker status. No completion percentage is estimated from elapsed time.")
        explanation = explanations.get(progress.get("stage"), fallback) if busy or state not in {"failed", "timed-out", "cancelled", "held"} else fallback
        hold = snapshot.get("storage_hold")
        if ended and type(hold) is dict:
            explanation = "The toolkit did not start because retained reports need review. Open Review scanner storage. "
            if hold.get("kind") == "free-space":
                facts = []
                for key, label in (("required_bytes", "required"), ("free_bytes", "available")):
                    value = hold.get(key)
                    if type(value) is int and 0 <= value <= 2**64:
                        facts.append(f"{label}: {value / 1024**3:.2f} GiB")
                explanation = ("Zero-Breach did not start because its working volume lacks free space. "
                    + "; ".join(facts) + ". Review space on " + _literal(hold.get("volume"), 80)
                    + ". Native checks retain their own recorded result; coverage is incomplete. ")
            elif hold.get("kind") == "report-count":
                retained = hold.get("retained_reports")
                if type(retained) is int and retained < SCANNER_REPORT_COUNT_MAX:
                    explanation += "You can allow one extra report for the next scan, if the fresh review permits it. "
                explanation += "You can change the saved count, choose Unlimited, or delete eligible reports. "
                explanation += "Export alone does not free slots. "
            elif hold.get("kind") != "free-space":
                explanation += "Count settings do not bypass byte, free-space or managed inventory checks. "
            explanation += "No evidence was deleted automatically."
        if (native_checks_finished and progress.get("stage") in {"toolkit", "native"}
                and state not in {"failed", "timed-out", "cancelled"}
                and snapshot.get("lifecycle") != "draining"):
            explanation = ("Native checks finished; report aggregation is pending. "
                           "The selected toolkit work must settle before findings and coverage gaps are assembled."
                           if progress.get("stage") == "toolkit" else
                           "Native checks finished; report aggregation is pending. Next: assemble findings and explicit coverage gaps.")
        if state == "timed-out":
            explanation = "The selected time budget expired. Partial results are retained; this is incomplete coverage. Choose a larger next-run budget to retry."
        if (progress.get("stage") == "finished" and state == "incomplete"
                and not (type(hold) is dict and hold.get("kind") == "free-space")):
            explanation = ("Some selected checks were unavailable or stopped early. "
                           "Review the hits and the areas the scan could not check. "
                           "A clean verdict requires more evidence.")
        self.stage_explanation.setText(explanation)
        planned = progress.get("planned_stages")
        finished_stages = progress.get("finished_stages")
        planned = planned if type(planned) in (tuple, list) else ()
        finished_stages = finished_stages if type(finished_stages) in (tuple, list) else ()
        for key, chip in self.stage_chips.items():
            selected = key in planned
            done = selected and key in finished_stages
            current = selected and key == progress.get("stage") and busy
            checks_finished = key == "native" and native_checks_finished
            if key == "native":
                title = "Native · checks finished" if checks_finished else "Native"
                if chip.text() != title:
                    chip.setText(title)
                tooltip = (("This request's native checks finished; the overall workflow has ended. " if ended else
                            "This request's native checks finished; report aggregation is pending. ") +
                           "Completion does not establish a clean PC or grant response authority."
                           if checks_finished else "A finished workflow stage is not a clean-host verdict.")
                if chip.toolTip() != tooltip:
                    chip.setToolTip(tooltip)
            accent = "#4ade80" if done else "#38bdf8" if current or checks_finished else "#64748b"
            chip.setStyleSheet(f"color:{accent};border:1px solid {accent};border-radius:4px;padding:3px;")
            chip_status = ("checks finished; workflow ended" if checks_finished and ended else
                           "checks finished; report aggregation pending" if checks_finished else
                           "finished" if done else "current" if current else
                           "not completed; workflow ended" if selected and ended else
                           "pending" if selected else "not scheduled")
            chip.setAccessibleName(f"{chip.text()}: {chip_status}")
        if self.progress_ring.percent is None:
            self.progress_count.setText("Indeterminate · the worker has not supplied a completion count.")
        else:
            self.progress_count.setText(f"Overall {self.progress_ring.percent}% · measured workflow fraction" +
                                        (f" · {finished}/{total} stages finished" if type(finished) is int and type(total) is int else ""))
        self._apply_readers(snapshot, readers)
        _set_enabled(self.cancel_button, busy and snapshot.get("active_action") != "automatic_probe")
        _set_enabled(self.auto_scan_save, not busy)
        usage = snapshot.get("resource_usage")
        usage = usage if type(usage) is dict else {}

        cpu = usage.get("cpu_percent", usage.get("cpu"))
        memory = usage.get("rss_mib", usage.get("memory_mib"))
        read, written = usage.get("read_bytes"), usage.get("write_bytes")
        io = (f"{_resource_number(read, ' MiB', 1024**2)} read / "
              f"{_resource_number(written, ' MiB', 1024**2)} written"
              if type(read) in (int, float) and type(written) in (int, float) else "unavailable")
        alive = usage.get("process_alive")
        presence = "running" if alive is True else "stopped" if alive is False else "liveness unavailable"
        self.resources.setText(f"Toolkit process · {presence} · latest available sample\n"
                               f"CPU: {_resource_number(cpu, '%')}     RAM: {_resource_number(memory, ' MiB')}\nI/O: {io}")
        admin = snapshot.get("admin_state", usage.get("admin_state"))
        if type(admin) is dict and admin.get("verified") is True:
            token = "Elevated token" if admin.get("elevated") is True else "Ordinary-user token"
            integrity = _literal(admin.get("integrity", "not reported"), 60)
            self.privileges.setText(f"Privilege verification: {token} · integrity: {integrity}. No new authority is granted.")
        else:
            self.privileges.setText("Privilege verification: unavailable or not yet verified. Coverage limits remain in effect.")

    def _apply_hits(self, snapshot, progress, planned):
        busy = snapshot.get("busy") is True
        toolkit = _match_summary(snapshot)
        if not toolkit and "toolkit" in planned:
            toolkit = ("Zero-Breach counts pending the retained report." if busy else
                       "Zero-Breach counts unavailable for this attempt.")
        native = ""
        if "native" in planned:
            native = "Native advisory counts pending." if busy else "Native advisory counts unavailable for this attempt."
            result = snapshot.get("native_scan_completion")
            request = progress.get("request_id")
            if (type(request) is str and len(request) == 32 and type(result) is dict and result.get("request_id") == request
                    and type(result.get("lifecycle_generation")) is int and result["lifecycle_generation"] > 0
                    and result.get("request_finished") is True and result.get("collector_finished") is True):
                counts = result.get("finding_counts")
                if (type(counts) is dict
                        and all(type(counts.get(key)) is int and 0 <= counts[key] <= 2**31 - 1
                                for key in ("advisory", "omitted"))
                        and counts["omitted"] <= counts["advisory"]):
                    native = f"Native SpywareGuard: {counts['advisory']} advisory hits"
                    if counts["omitted"]:
                        native += f" · omitted details: {counts['omitted']}"
                    native += ". Coverage incomplete." if result.get("coverage_incomplete") is True else "."
        lines = [line for line in (native, toolkit) if line]
        self.hits.setText("Hits · " + ("\n".join(lines) if lines else "Counts will appear when the scan reports them."))

    def _apply_readers(self, snapshot, readers):
        visible = set()
        activities, files = [], []
        current = {}
        current_terminal = False
        scrollbar = self.steps_scroll.verticalScrollBar()
        position = scrollbar.value()
        for source in ("native", "toolkit"):
            value = readers.get(source)
            title = "Native SpywareGuard" if source == "native" else "Zero-Breach"
            if type(value) is not dict:
                self.scanner_summaries[source].setText(f"{title}: no request-bound reader progress available")
                continue
            terminal = (value.get("state") in {"completed", "complete", "cancelled", "failed", "timed-out",
                                               "incomplete", "held", "error", "not-started", "not-scanned", "preview", "references", "withdrawn"}
                        or (not snapshot.get("busy") and snapshot.get("lifecycle") == "terminal"))
            percent = _measured(value.get("overall_percent"), maximum=100)
            value_state = _literal(value.get("state", "unknown"), 32)
            if terminal and value_state in {"running", "queued", "cancelling"}:
                value_state += " (last reported; request ended)"
            percentage = f"{min(percent, 99) if snapshot.get('busy') and not terminal else percent:.0f}%" if percent is not None else "indeterminate"
            self.scanner_summaries[source].setText(f"{title}: {value_state} · {percentage}")
            task = _literal(value.get("current_task"), 500)
            item = _literal(value.get("current_file"), 800)
            if task:
                activities.append(f"{title}: {task}")
            if item:
                item_done, item_total = _measured(value.get("item_completed")), _measured(value.get("item_total"))
                if item_done is not None and item_total and item_done <= item_total:
                    item += f" · {item_done:,.0f}/{item_total:,.0f} {_literal(value.get('item_unit', 'items'), 40)} ({item_done * 100 / item_total:.0f}%)"
                files.append(f"{title}: {item}")
            if (value.get("state") in {"running", "queued", "cancelling"} or not current
                    or current.get("state") not in {"running", "queued", "cancelling"}):
                current = value
                current_terminal = terminal
            rows = value.get("steps")
            for step in rows[:64] if type(rows) in (tuple, list) else ():
                if type(step) is not dict or type(step.get("id")) is not str:
                    continue
                key = source + ":" + step["id"][:100]
                visible.add(key)
                row = self.step_rows.get(key)
                if row is None:
                    row = ScanStepRow(self.steps_body)
                    self.step_rows[key] = row
                    self.steps_layout.insertWidget(self.steps_layout.count() - 1, row)
                row.apply(title, step, terminal=terminal)
                _set_visible(row, True)
        for key, row in tuple(self.step_rows.items()):
            if key not in visible:
                self.steps_layout.removeWidget(row)
                row.deleteLater()
                del self.step_rows[key]
        _set_visible(self.steps_scroll, bool(visible) and self.step_toggle.isChecked())
        _set_visible(self.step_toggle, bool(visible))
        scrollbar.setValue(position)
        self.activity.setText(("Current task: " if snapshot.get("busy") else "Last observed task: ") + ("\n".join(activities) if activities else
                              "waiting for structured reader activity" if snapshot.get("busy") else "no scan is running"))
        self.current_file.setText(("Current file: " if snapshot.get("busy") else "Last observed file: ") +
                                 ("\n".join(files) if files else "not supplied by the current reader; no file name is inferred."))
        self._timing_current = current
        self._apply_timing(snapshot, current)
        item_done, item_total = _measured(current.get("item_completed")), _measured(current.get("item_total"))
        observed_item = bool(current.get("current_file")) or item_done is not None
        _set_visible(self.item_progress, observed_item)
        _set_visible(self.item_caption, observed_item)
        if item_done is not None and item_total and item_done <= item_total:
            percent = item_done * 100 / item_total
            _set_progress(self.item_progress, int(percent), f"Current item {percent:.0f}%")
            unit = _literal(current.get("item_unit", "items"), 60)
            eta = "— (item ended)" if current_terminal else _duration(current.get("item_remaining_s"))
            self.item_caption.setText(f"Current item: {item_done:,.0f}/{item_total:,.0f} {unit} · item ETA {eta}")
        else:
            _set_progress(self.item_progress, 0, "Current item indeterminate · no known total")
            eta = "— (item ended)" if current_terminal else "Calculating"
            self.item_caption.setText("Current item: " + (f"{item_done:,.0f} observed; " if item_done is not None else "") + "total unknown · item ETA " + eta)
        reason = snapshot.get("message") if snapshot.get("state") in {"held", "failed", "timed-out", "cancelled", "incomplete", "stopping"} else ""
        gap = snapshot.get("focus_lease_gap")
        if type(gap) is str and gap:
            reason = str(reason or "") + "\n" + gap
        self.outcome.setText(_literal(reason, 1800))
        _set_visible(self.outcome, bool(reason))


class CuratedScannerWidget(QWidget):
    analysis_requested = Signal()

    def __init__(self, manager, parent=None, *, controller=None):
        super().__init__(parent)
        self.controller = controller or get_curated_tools_controller(manager)
        self._credits_dialog = None
        self._credits_requested = False
        self._settings_dialog = None
        self._after_action_dialog = None
        self._advanced_dialog = None
        layout = QVBoxLayout(self)
        if hasattr(self.controller, "activities"):
            from angerona.gui.action_progress import ActionProgressView
            self.progress_view = ActionProgressView(self.controller.activities, self, config=_config(manager))
            layout.addWidget(self.progress_view)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(7)
        title = _label("Zero-Breach Toolkit")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        layout.addWidget(_label("Checks known spyware traces using the pinned toolkit. Coverage, gaps and findings remain separate."))
        self.status = _label()
        layout.addWidget(self.status)
        row = QGridLayout()
        self._primary_actions = row
        self.install_button = QPushButton("Install / repair")
        self.run_button = QPushButton("Run scan")
        self.priority_button = QPushButton("Spyware Scan")
        style_spyware_scan_button(self.priority_button)
        self.cancel_button = QPushButton("Stop scan")
        self.credits_button = QPushButton("Credits")
        self._primary_buttons = (self.install_button, self.run_button, self.priority_button, self.cancel_button, self.credits_button)
        for index, button in enumerate(self._primary_buttons):
            row.addWidget(button, 0, index)
        layout.addLayout(row)
        self.install_button.clicked.connect(self.controller.prepare)
        self.run_button.clicked.connect(lambda: self._scan())
        self.priority_button.clicked.connect(lambda: self._scan(priority=True))
        self.cancel_button.clicked.connect(self.controller.cancel)
        self.credits_button.clicked.connect(self._request_credits)
        self.priority_controls = SpywareScanControls(manager, self, controller=self.controller, scope_controls=False)
        layout.addWidget(self.priority_controls)
        mode_row = QFormLayout()
        self.mode = ClickChoice()
        self.mode.setMinimumContentsLength(16)
        self.mode.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        for label, value in (("Standard system checks", "default"), ("Entire PC · supported full checks", "full"),
                             ("Browser checks", "browser"), ("Selected evidence", "targeted")):
            self.mode.addItem(label, value)
        self.mode.setCurrentIndex(self.mode.findData("full"))
        mode_row.addRow("Scope", self.mode)
        mode_row.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        layout.addLayout(mode_row)
        self.options_toggle = QToolButton()
        self.options_toggle.setText("Scan options")
        self.options_toggle.setToolTip("Choose local evidence, indicator files and optional scan flags.")
        self.options_toggle.setCheckable(True)
        self.options_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.options_toggle.setArrowType(Qt.ArrowType.RightArrow)
        layout.addWidget(self.options_toggle)
        self.options = QGroupBox()
        options_layout = QVBoxLayout(self.options)
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.device = ClickChoice()
        self.device.setMinimumContentsLength(16)
        self.device.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        for label, value in (("Desktop / selected files", "desktop"), ("Existing Android collection", "android"),
                             ("iPhone backup", "backup"), ("iPhone filesystem export", "filesystem"),
                             ("iPhone sysdiagnose", "sysdiagnose")):
            self.device.addItem(label, value)
        form.addRow("Evidence type", self.device)
        self.targets = QPlainTextEdit()
        self.targets.setPlaceholderText("Selected local paths, one per line; never enter a backup password here.")
        self.targets.setMaximumHeight(76)
        self.targets.document().setMaximumBlockCount(16)
        form.addRow("Local evidence", self.targets)
        self.iocs = QLineEdit()
        self.iocs.setMaxLength(2048)
        self.iocs.setPlaceholderText("Optional local indicator file")
        form.addRow("Custom indicators", self.iocs)
        options_layout.addLayout(form)
        choose = QHBoxLayout()
        select_folder = QPushButton("Choose folder…")
        select_file = QPushButton("Choose file…")
        select_iocs = QPushButton("Indicator file…")
        select_folder.clicked.connect(lambda: self._choose(True))
        select_file.clicked.connect(lambda: self._choose(False))
        select_iocs.clicked.connect(self._choose_iocs)
        for button in (select_folder, select_file, select_iocs):
            choose.addWidget(button)
        choose.addStretch(1)
        options_layout.addLayout(choose)
        self.quick = QCheckBox("Quick scan (records skipped hashing)")
        self.preview = QCheckBox("Preview scope without claiming a completed scan")
        self.extended = QCheckBox("Include existing Windows event records")
        for check in (self.quick, self.preview, self.extended):
            options_layout.addWidget(check)
        options_layout.addWidget(_label("Built-in indicators run offline. Advanced toolkit options explain standalone "
                                        "encrypted backups, pattern engines and device acquisition."))
        self.options.hide()
        self.options_toggle.toggled.connect(self._toggle_options)
        layout.addWidget(self.options)
        actions = QGridLayout()
        self._secondary_actions = actions
        self.verify_button = QPushButton("Verify / self-test")
        self.settings_button = QPushButton("Settings")
        self.analysis_button = QPushButton("Analysis / sandbox")
        self.advanced_button = QPushButton("Advanced toolkit options…")
        self.revert_button = QPushButton("Revert")
        self.project_button = QPushButton("Project ↗")
        self._secondary_buttons = (self.verify_button, self.settings_button, self.analysis_button,
                                   self.advanced_button, self.revert_button, self.project_button)
        for index, button in enumerate(self._secondary_buttons):
            actions.addWidget(button, index // 3, index % 3)
        layout.addLayout(actions)
        self.verify_button.clicked.connect(self.controller.self_test)
        self.settings_button.clicked.connect(self._show_settings)
        self.analysis_button.clicked.connect(self.analysis_requested.emit)
        self.advanced_button.clicked.connect(self._show_advanced)
        self.revert_button.clicked.connect(self._revert)
        self.project_button.clicked.connect(lambda: _open_link(_PROJECT))
        self.results = QPlainTextEdit()
        self.results.setReadOnly(True)
        self.results.setUndoRedoEnabled(False)
        self.results.setMinimumHeight(130)
        self.results.document().setMaximumBlockCount(2000)
        self.results.setPlaceholderText("Scan coverage and results appear here. Source-analysis sandbox controls are separate from host scanning.")
        layout.addWidget(self.results, 1)
        review = QHBoxLayout()
        self.investigate_button = QPushButton("Investigate")
        self.investigate_button.setToolTip("Open the detailed after-action report and response availability.")
        self.trace_button = QPushButton("Trace evidence")
        self.investigate_button.clicked.connect(self._investigate)
        self.trace_button.clicked.connect(lambda: self._investigate(trace=True))
        review.addWidget(self.investigate_button)
        review.addWidget(self.trace_button)
        layout.addLayout(review)
        initial = self.controller.snapshot()
        self._apply(initial)
        self._presentation = _ScanViewPresentation(self, initial)
        self.controller.status_changed.connect(self._presentation.receive)
        self.controller.credits_ready.connect(self._show_credits)
        self._action_columns = None
        self._reflow_actions()

    def _toggle_options(self, opened):
        self.options.setVisible(opened)
        self.options_toggle.setArrowType(Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow)

    def _reflow_actions(self):
        if not hasattr(self, "_secondary_buttons"):
            return
        parent = self.parentWidget()
        available = min(self.width(), parent.width()) if parent is not None else self.width()
        available -= self.layout().contentsMargins().left() + self.layout().contentsMargins().right()

        def fitted(buttons, maximum, grid):
            for button in buttons:
                button.ensurePolished()
            spacing = max(0, grid.horizontalSpacing())
            for count in range(maximum, 0, -1):
                widths = [max(button.minimumSizeHint().width() for button in buttons[column::count])
                          for column in range(count)]
                if sum(widths) + spacing * (count - 1) <= available:
                    return count
            return 1

        columns = (fitted(self._primary_buttons, 5, self._primary_actions),
                   fitted(self._secondary_buttons, 3, self._secondary_actions))
        if columns == getattr(self, "_action_columns", None):
            return
        self._action_columns = columns
        for grid, buttons, count in ((self._primary_actions, self._primary_buttons, columns[0]),
                                     (self._secondary_actions, self._secondary_buttons, columns[1])):
            for button in buttons:
                grid.removeWidget(button)
            for column in range(6):
                grid.setColumnStretch(column, 0)
            for index, button in enumerate(buttons):
                grid.addWidget(button, index // count, index % count)
            grid.setColumnStretch(count, 1)
            grid.invalidate()
        self.updateGeometry()

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        self._reflow_actions()

    def _choose(self, folder):
        selected = QFileDialog.getExistingDirectory(self, "Select local evidence") if folder else QFileDialog.getOpenFileName(self, "Select local evidence")[0]
        if selected:
            lines = self.targets.toPlainText().splitlines()
            self.targets.setPlainText("\n".join((*lines, selected)[-16:]))
            self.mode.setCurrentIndex(self.mode.findData("targeted"))

    def _choose_iocs(self):
        selected = QFileDialog.getOpenFileName(self, "Select local indicator file")[0]
        if selected:
            self.iocs.setText(selected)

    def _scan(self, *, priority=False):
        targets = tuple(line.strip() for line in self.targets.toPlainText().splitlines() if line.strip())[:16]
        device = self.device.currentData()
        mode = self.mode.currentData()
        if (mode == "targeted" or device != "desktop") and not targets:
            self.status.setText("Choose the local evidence path before scanning.")
            self.options_toggle.setChecked(True)
            return
        selected = dict(mode="targeted" if device == "android" else mode,
                        targets=targets, phone=device in {"backup", "filesystem", "sysdiagnose"},
                        ios_input=device if device in {"backup", "filesystem", "sysdiagnose"} else "backup",
                        quick=self.quick.isChecked(), preview=self.preview.isChecked(),
                        extended_windows=self.extended.isChecked(), include_feeds=False,
                        iocs=(self.iocs.text().strip(),) if self.iocs.text().strip() else ())
        if selected["quick"] and selected["mode"] == "targeted":
            self.status.setText("Quick mode applies to desktop checks; turn it off for selected evidence.")
            return
        if priority:
            self.priority_controls.start(**selected)
        else:
            selected.update(priority=self.priority_controls.priority.currentData(),
                            max_cpu_percent=self.priority_controls.cpu.value(),
                            max_memory_mib=self.priority_controls.memory.value())
            self.controller.scan(**selected)

    def _apply(self, state):
        busy = bool(state.get("busy"))
        verified = bool(state.get("verified"))
        executable = state.get("execution_available") is not False
        enabled = bool(getattr(_config(self.controller.manager), "github_tools_enabled", True))
        summary = _match_summary(state)
        self.status.setText(f"{_literal(state.get('state', 'unknown'), 80)} · v{_literal(state.get('version', '0.1.10'), 40)}\n"
                            + _literal(state.get("message"), 1200)
                            + ("\n" + summary if summary else ""))
        _set_enabled(self.install_button, not busy and enabled)
        _set_enabled(self.run_button, not busy and verified and enabled and executable)
        _set_enabled(self.priority_button, not self.controller._closed)
        _set_enabled(self.advanced_button, not busy)
        _set_enabled(self.verify_button, not busy and verified and enabled and executable)
        _set_enabled(self.cancel_button, busy and state.get("active_action") != "automatic_probe")
        _set_enabled(self.revert_button, not busy and bool(state.get("installed")))
        _set_enabled(self.credits_button, not busy)
        _set_enabled(self.settings_button, not busy)
        selected = {key: state[key] for key in ("state", "message", "coverage", "coverage_incomplete", "match_counts", "findings", "details", "report", "latest_report", "partial_result")
                    if key in state}
        content = _literal(selected)
        _set_document_text(self.results, content)

    def _revert(self):
        if QMessageBox.question(self, "Revert Zero-Breach integration",
                                "Disable automatic scanner preparation and retire its managed scanner copy? "
                                "Preferences, reports and imported source are preserved.",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.controller.revert()

    def _investigate(self, *, trace=False):
        self._after_action_dialog = self.controller.show_after_action(trace=trace)

    def _show_settings(self):
        if self._settings_dialog is not None and isValid(self._settings_dialog):
            self._settings_dialog.show()
            self._settings_dialog.raise_()
            return
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.setWindowTitle("GitHub tools settings")
        dialog.resize(580, 430)
        layout = QVBoxLayout(dialog)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(CuratedToolsSettings(self.controller, dialog))
        layout.addWidget(scroll)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        self._settings_dialog = dialog
        dialog.show()

    def _show_advanced(self):
        if self._advanced_dialog is not None and isValid(self._advanced_dialog):
            self._advanced_dialog.show()
            self._advanced_dialog.raise_()
            return
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.setWindowTitle("Zero-Breach — advanced toolkit options")
        dialog.resize(680, 470)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(
            "Integrated adapter\n"
            "Default, full, browser and selected-evidence checks; existing Android collections; "
            "iPhone backup/filesystem/sysdiagnose inputs; preview, quick checks and local indicator files. "
            "Actual coverage and missing dependencies are recorded in each report.\n\n"
            "Standalone advanced capabilities\n"
            "The upstream release also provides encrypted-backup prompts, optional YARA patterns, "
            "indicator updates, evidence ZIP exports and AndroidQF acquisition. Android acquisition "
            "changes device state and needs its owner's consent. Backup passwords belong in the "
            "toolkit's private terminal prompt.\n\n"
            "Advanced execution inside Angerona is held until its separate dependency/acquisition "
            "runtime is reviewed. Use the official pinned release below to review standalone setup. "
            "The included source, versions and required notices remain available in Credits.\n\n"
            "A host-evidence scan and the Source Library's analysis sandbox have different scopes. "
            "Sandbox readiness and response authority retain their existing checks.")
        layout.addWidget(text, 1)
        row = QHBoxLayout()
        release = QPushButton("Official pinned release / downloads ↗")
        release.clicked.connect(lambda: _open_link(_RELEASE))
        status = QPushButton("Check advanced adapter status")
        status.setEnabled(self.controller.snapshot().get("execution_available") is not False)
        status.setToolTip(_literal(self.controller.snapshot().get("execution_hold_reason", ""), 1000))
        status.clicked.connect(self.controller.open_tool)
        row.addWidget(release)
        row.addWidget(status)
        layout.addLayout(row)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        self._advanced_dialog = dialog
        dialog.show()

    def _show_credits(self, rows):
        requested, self._credits_requested = self._credits_requested, False
        if not requested or not self.isVisible():
            return
        if self._credits_dialog is not None and isValid(self._credits_dialog):
            self._credits_dialog.close()
        dialog = QDialog(self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.setWindowTitle("GitHub tools — credits and licenses")
        dialog.resize(720, 520)
        layout = QVBoxLayout(dialog)
        layout.addWidget(_label("Upstream projects, research providers and applicable licenses. Inclusion does not imply endorsement."))
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText("\n\n".join(_literal(row, 12000) for row in rows[:64])[:96000])
        layout.addWidget(text, 1)
        links = QHBoxLayout()
        choices = QComboBox()
        choices.setObjectName("CreditsLinks")
        choices.setAccessibleName("Credited project and license links")
        choices.setMinimumContentsLength(18)
        choices.setMaximumWidth(440)
        choices.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        seen = set()
        for row in rows[:64]:
            if type(row) is not dict:
                continue
            for key in ("url", "license_url", "source_url", "notice_url"):
                url = row.get(key)
                if type(url) is str and len(url) <= 512 and url not in seen:
                    seen.add(url)
                    choices.addItem(_literal(row.get("name", "Project"), 40) + " — " + url, url)
        open_link = QPushButton("Open selected link ↗")
        open_link.setEnabled(bool(seen))
        open_link.clicked.connect(lambda: _open_link(choices.currentData()))
        links.addWidget(choices, 1)
        links.addWidget(open_link)
        layout.addLayout(links)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        self._credits_dialog = dialog
        dialog.show()

    def _request_credits(self):
        self._credits_requested = True
        if not self.controller.load_credits():
            self._credits_requested = False

    def showEvent(self, event):  # noqa: N802
        super().showEvent(event)
        self._presentation.flush()
        if self._presentation.latest.get("state") == "not_loaded":
            self.controller.refresh()


class GitHubToolsDialog(QDialog):
    def __init__(self, manager, parent=None, *, open_forge=None):
        super().__init__(parent)
        self.setWindowTitle("Angerona — GitHub tools")
        self.setModal(False)
        self.setMinimumSize(560, 400)
        screen = self.screen()
        available = screen.availableGeometry() if screen is not None else None
        self.resize(min(1040, int(available.width() * .9)) if available else 1040,
                    min(740, int(available.height() * .88)) if available else 740)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.scanner = CuratedScannerWidget(manager, self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.scanner)
        self.tabs.addTab(scroll, "Curated scanners")
        from angerona.gui.github_tools import GitHubToolsPanel
        cfg = _config(manager)
        from angerona.core.data_paths import data_dir
        configured_root = getattr(cfg, "data_dir", None)
        root = Path(configured_root) if configured_root is not None else data_dir()
        self.source_library = GitHubToolsPanel(self, root=root / "github-source-library")
        source_scroll = QScrollArea()
        source_scroll.setWidgetResizable(True)
        source_scroll.setWidget(self.source_library)
        self.tabs.addTab(source_scroll, "Source library & analysis")
        self.source_scroll = source_scroll
        from angerona.core.github_tool_catalog import GitHubToolCatalog
        from angerona.core.community_tool_adapters import CommunityToolService
        from angerona.core.rule_playbook_library import RulePlaybookLibrary
        from angerona.gui.community_tools import CommunityToolsPanel
        from angerona.gui.rules_playbooks import RulesPlaybooksPanel
        controller = self.scanner.controller
        class ScannerProxy:
            def __getattr__(self, name):
                return getattr(controller.community_service(), name)
        catalog = GitHubToolCatalog(root / "github-source-library")
        self.community_service = CommunityToolService(root / "community-tools", catalog=catalog, curated=ScannerProxy())
        self.suggested = CommunityToolsPanel(self.community_service, self, open_source_review=self.open_source_library)
        self.tabs.addTab(self.suggested, "Suggested tools")
        self.rule_library = RulePlaybookLibrary(root / "rule-playbook-library", catalog=catalog)
        self.rules = RulesPlaybooksPanel(self.rule_library, self, open_forge=open_forge,
                                        open_source_review=self.open_source_library, open_settings=self.open_settings, cfg=cfg)
        self.tabs.addTab(self.rules, "Rules & Playbooks")
        settings = QScrollArea()
        settings.setWidgetResizable(True)
        settings.setWidget(CuratedToolsSettings(self.scanner.controller, self))
        self.settings_scroll = settings
        self.tabs.addTab(settings, "Settings")
        self.scanner.analysis_requested.connect(self.open_analysis)
        layout.addWidget(self.tabs)
        from angerona.gui.window_fit import install_window_fit
        self._window_fit = install_window_fit(self)
        self.tabs.setCurrentWidget(self.suggested)

    def open_analysis(self):
        self.tabs.setCurrentWidget(self.source_scroll)
        self.source_library.tabs.setCurrentWidget(self.source_library.analysis_lab)

    def open_source_library(self):
        self.tabs.setCurrentWidget(self.source_scroll)
        self.source_library.tabs.setCurrentIndex(0)

    def open_settings(self):
        self.tabs.setCurrentWidget(self.settings_scroll)

    def closeEvent(self, event):  # noqa: N802
        self.source_library.cancel_pending()
        self.source_library.analysis_lab.cancel_pending()
        self.suggested.analysis_lab.cancel_pending()
        for entry in tuple(self.suggested._operations.values()):
            entry["operation"].cancel()
        self.rules.cancel()
        super().closeEvent(event)

    def owned_workers(self):
        source = getattr(self.source_library, "_worker", None)
        analysis = getattr(self.source_library.analysis_lab, "_worker", None)
        return (*self.suggested.owned_workers(), *self.rules.owned_workers(), *((source,) if source else ()), *((analysis,) if analysis else ()))

    def custody_released(self):
        return self.suggested.custody_released() and self.rules.custody_released()

    def retire_view(self):
        # Source-review work belongs to its view; scanner work belongs to App.
        self.source_library._lifetime["closed"] = True
        self.source_library.cancel_pending()
        self.source_library.analysis_lab._lifetime["closed"] = True
        self.source_library.analysis_lab.cancel_pending()
        self.suggested.request_shutdown()
        self.rules.request_shutdown()
        self.close()
