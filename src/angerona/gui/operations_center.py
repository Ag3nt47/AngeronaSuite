"""Interactive, local-only operations workspace for Angerona.

The Flow Dashboard is intentionally a presentation and orchestration layer over
the existing bounded stores.  It does not duplicate collection, accept SQL, or
add a remote shell.  Potentially slow hunts and inventory collection execute in
short-lived worker threads and return to the Qt thread through a signal.
"""
from __future__ import annotations

import json
import platform
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QTimer,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from angerona.core.operations_center import LocalOperationsCenter
from angerona.core.security_interop import OSQUERY_TEMPLATES, discover_osquery
from angerona.gui.animations import begin_loading, finish_loading
from angerona.gui.header_controls import motion_allowed

_CASE_STATUSES = ("open", "investigating", "contained", "resolved", "closed")
_SEVERITY = ("Info", "Low", "Medium", "High", "Critical")


def _stamp(value: float) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, TypeError, ValueError):
        return "—"


def _plain(value: Any, limit: int = 500) -> str:
    if isinstance(value, (dict, list, tuple)):
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    else:
        rendered = str(value)
    return rendered[:limit]


class RadialMetricCard(QWidget):
    """Compact radial infographic with a restrained hover expansion."""

    clicked = Signal(str)

    def __init__(
        self,
        key: str,
        title: str,
        color: str,
        config: Any | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.key = key
        self.title = title
        self.color = QColor(color)
        self._config = config
        self.value = "—"
        self.detail = "Waiting for local data"
        self.ratio = 0.0
        self._hover = 0.0
        self.setMinimumSize(150, 156)
        self.setCursor(Qt.PointingHandCursor)
        self.setAccessibleName(title)
        self._animation = QPropertyAnimation(self, b"hoverAmount", self)
        self._animation.setDuration(180)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)

    def set_metric(self, value: Any, ratio: float, detail: str) -> None:
        self.value = str(value)
        self.ratio = max(0.0, min(float(ratio), 1.0))
        self.detail = str(detail)
        self.setToolTip(f"<b>{self.title}</b><br>{self.detail}")
        self.setAccessibleDescription(self.detail)
        self.update()

    def _get_hover(self) -> float:
        return self._hover

    def _set_hover(self, value: float) -> None:
        self._hover = max(0.0, min(float(value), 1.0))
        self.update()

    hoverAmount = Property(float, _get_hover, _set_hover)

    def _animate(self, end: float) -> None:
        self._animation.stop()
        if not motion_allowed(self._config):
            self._set_hover(end)
            return
        self._animation.setStartValue(self._hover)
        self._animation.setEndValue(end)
        self._animation.start()

    def enterEvent(self, event) -> None:
        self._animate(1.0)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._animate(0.0)
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit(self.key)
        super().mouseReleaseEvent(event)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(2.0, 2.0, -2.0, -2.0)
        background = QColor("#0b1320")
        background.setAlpha(245)
        border = QColor(self.color)
        border.setAlpha(70 + int(120 * self._hover))
        painter.setBrush(background)
        painter.setPen(QPen(border, 1.0 + self._hover))
        painter.drawRoundedRect(rect, 14.0 + 4.0 * self._hover, 14.0 + 4.0 * self._hover)

        ring_size = 78.0 + 7.0 * self._hover
        ring = QRectF(
            (self.width() - ring_size) / 2.0,
            15.0 - 2.0 * self._hover,
            ring_size,
            ring_size,
        )
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor("#17283b"), 8.0, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(ring, 0, 360 * 16)
        painter.setPen(QPen(self.color, 8.0, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(ring, 90 * 16, -int(360 * 16 * self.ratio))

        painter.setPen(QColor("#f8fafc"))
        value_font = painter.font()
        value_font.setBold(True)
        value_font.setPointSizeF(15.0 + self._hover)
        painter.setFont(value_font)
        painter.drawText(ring, Qt.AlignCenter, self.value)

        painter.setPen(self.color)
        title_font = painter.font()
        title_font.setPointSizeF(9.0)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(QRectF(6, 102, self.width() - 12, 20), Qt.AlignCenter, self.title)

        painter.setPen(QColor("#8ea5bf"))
        detail_font = painter.font()
        detail_font.setPointSizeF(7.3 + 0.4 * self._hover)
        detail_font.setBold(False)
        painter.setFont(detail_font)
        painter.drawText(
            QRectF(12, 123, self.width() - 24, 29),
            Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap,
            self.detail,
        )


class FlowMetricDeck(QWidget):
    """Radial cards connected by a lightweight animated evidence flow."""

    metric_clicked = Signal(str)

    def __init__(self, config: Any | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._config = config
        self.setMinimumHeight(166)
        self.cards: dict[str, RadialMetricCard] = {}
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(12)
        for key, title, color in (
            ("cases", "CASE FLOW", "#38bdf8"),
            ("evidence", "EVIDENCE", "#c084fc"),
            ("audit", "AUDIT TRUST", "#34d399"),
            ("assets", "ASSET MAP", "#fbbf24"),
            ("detections", "DETECTIONS", "#fb7185"),
        ):
            card = RadialMetricCard(key, title, color, config, self)
            card.clicked.connect(self.metric_clicked)
            layout.addWidget(card, 1)
            self.cards[key] = card
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(90)
        self._timer.timeout.connect(self._advance)
        if motion_allowed(self._config):
            self._timer.start()

    def _advance(self) -> None:
        if not self.isVisible():
            return
        self._phase = (self._phase + 0.035) % 1.0
        self.update()

    def stop(self) -> None:
        self._timer.stop()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if len(self.cards) < 2:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        ordered = list(self.cards.values())
        for left, right in zip(ordered, ordered[1:]):
            start = left.geometry().center()
            end = right.geometry().center()
            path = QPainterPath(QPointF(start))
            midpoint = (start.x() + end.x()) / 2.0
            path.cubicTo(midpoint, start.y() - 28, midpoint, end.y() + 28, end.x(), end.y())
            painter.setPen(QPen(QColor(34, 211, 238, 45), 2.0))
            painter.drawPath(path)
            if self._timer.isActive():
                dot = path.pointAtPercent(self._phase)
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor("#67e8f9"))
                painter.drawEllipse(dot, 2.6, 2.6)


class OperationsCenterDialog(QDialog):
    """Resizable Flow Dashboard backed by the Local Operations Center."""

    task_done = Signal(str, object, str)

    def __init__(
        self,
        service: LocalOperationsCenter,
        *,
        callbacks: dict[str, Callable[[], None]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.callbacks = dict(callbacks or {})
        self._tasks: set[str] = set()
        self._task_loading: dict[str, str] = {}
        self._hunt_rows: tuple[Any, ...] = ()
        self.setWindowTitle("Angerona Flow Dashboard — Local SOC")
        self.setMinimumSize(820, 590)
        self.resize(1320, 860)
        self.setModal(False)
        self.task_done.connect(self._finish_task)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        heading = QHBoxLayout()
        title = QLabel("ANGERONA  /  FLOW DASHBOARD")
        title.setStyleSheet("color:#38bdf8;font-size:20px;font-weight:700;letter-spacing:2px")
        heading.addWidget(title)
        self.boundary = QLabel("● LOCAL ONLY  ·  NO REMOTE SHELL  ·  SIGNED DETECTIONS")
        self.boundary.setStyleSheet(
            "color:#34d399;background:#0b201b;border:1px solid #14532d;"
            "border-radius:10px;padding:5px 10px")
        heading.addWidget(self.boundary)
        heading.addStretch()
        self.busy = QLabel("")
        self.busy.setStyleSheet("color:#fbbf24")
        heading.addWidget(self.busy)
        refresh = QPushButton("↻ Refresh")
        refresh.clicked.connect(self.refresh_all)
        heading.addWidget(refresh)
        root.addLayout(heading)

        self.deck = FlowMetricDeck(getattr(service, "config", None), self)
        self.deck.metric_clicked.connect(self._open_metric)
        root.addWidget(self.deck)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview(), "Overview")
        self.tabs.addTab(self._build_cases(), "Cases")
        self.tabs.addTab(self._build_hunt(), "Hunt")
        self.tabs.addTab(self._build_assets(), "Assets")
        self.tabs.addTab(self._build_detections(), "Detection Content")
        self.tabs.addTab(self._build_interoperability(), "Parity & Interop")
        self.tabs.addTab(self._build_audit(), "Audit")
        from angerona.gui.context_info import attach_context_info
        self._context_info = attach_context_info(self.tabs, "operations")
        root.addWidget(self.tabs, 1)

        actions = QHBoxLayout()
        actions.addWidget(QLabel("Jump to:"))
        for label, key in (
            ("Drive / Network Scan", "scan"),
            ("Forensics", "forensics"),
            ("Red Team", "simulation"),
            ("Classic Dashboard", "classic"),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, name=key: self._callback(name))
            actions.addWidget(button)
        actions.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        actions.addWidget(close)
        root.addLayout(actions)

        self.refresh_all()

    def _panel(self, title: str, subtitle: str = "") -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setObjectName("Panel")
        layout = QVBoxLayout(frame)
        label = QLabel(title)
        label.setStyleSheet("color:#38bdf8;font-weight:700;font-size:14px")
        layout.addWidget(label)
        if subtitle:
            note = QLabel(subtitle)
            note.setWordWrap(True)
            note.setStyleSheet("color:#8ea5bf")
            layout.addWidget(note)
        return frame, layout

    @staticmethod
    def _table(columns: tuple[str, ...]) -> QTableWidget:
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _build_overview(self) -> QWidget:
        page = QWidget()
        layout = QGridLayout(page)
        layout.setColumnStretch(0, 1)
        layout.setColumnStretch(1, 1)
        cards = (
            (
                "INVESTIGATE",
                "Run bounded hunts across normalized evidence, turn results into a case, "
                "and keep only integrity metadata in the case database.",
            ),
            (
                "CONTAIN",
                "Track investigation, containment, resolution, assignee, notes, legal "
                "hold, and sanitized exports without enabling autonomous destructive action.",
            ),
            (
                "UNDERSTAND",
                "Build a privacy-minimized local asset and software inventory, including "
                "module health and a runtime SBOM—never usernames, hostnames, or home paths.",
            ),
            (
                "IMPROVE",
                "Stage detection content in quarantine and activate it only when a trusted "
                "Ed25519 publisher signature passes the local policy gate.",
            ),
        )
        for index, (title, body) in enumerate(cards):
            panel, box = self._panel(title)
            text = QLabel(body)
            text.setWordWrap(True)
            text.setStyleSheet("font-size:13px;padding:8px")
            box.addWidget(text)
            layout.addWidget(panel, index // 2, index % 2)
        self.overview_note = QLabel("")
        self.overview_note.setWordWrap(True)
        self.overview_note.setStyleSheet(
            "color:#cbd5e1;background:#08111e;border:1px solid #1e3a55;"
            "border-radius:8px;padding:10px")
        layout.addWidget(self.overview_note, 2, 0, 1, 2)
        return page

    def _build_cases(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        create, form_box = self._panel("New case", "Create an attributed local investigation.")
        form = QHBoxLayout()
        self.case_title = QLineEdit()
        self.case_title.setPlaceholderText("Case title")
        self.case_assignee = QLineEdit()
        self.case_assignee.setPlaceholderText("Assignee (optional)")
        self.case_tags = QLineEdit()
        self.case_tags.setPlaceholderText("Tags, comma separated")
        add = QPushButton("+ Create")
        add.clicked.connect(self._create_case)
        for widget, stretch in (
            (self.case_title, 3), (self.case_assignee, 2),
            (self.case_tags, 2), (add, 0),
        ):
            form.addWidget(widget, stretch)
        form_box.addLayout(form)
        root.addWidget(create)

        split = QSplitter(Qt.Horizontal)
        left, left_box = self._panel("Case queue")
        filter_row = QHBoxLayout()
        self.case_filter = QComboBox()
        self.case_filter.addItem("All states", "")
        for status in _CASE_STATUSES:
            self.case_filter.addItem(status.title(), status)
        self.case_filter.currentIndexChanged.connect(self._refresh_cases)
        filter_row.addWidget(QLabel("Status:"))
        filter_row.addWidget(self.case_filter)
        filter_row.addStretch()
        left_box.addLayout(filter_row)
        self.case_table = self._table(
            ("ID", "Title", "Status", "Assignee", "Updated", "Evidence"))
        self.case_table.itemSelectionChanged.connect(self._show_case_detail)
        left_box.addWidget(self.case_table)
        split.addWidget(left)

        right, right_box = self._panel("Case detail", "Timeline and authenticated custody metadata.")
        self.case_detail = QTextEdit()
        self.case_detail.setReadOnly(True)
        right_box.addWidget(self.case_detail, 1)
        update_row = QHBoxLayout()
        self.case_status = QComboBox()
        self.case_status.addItems([item.title() for item in _CASE_STATUSES])
        self.case_update_assignee = QLineEdit()
        self.case_update_assignee.setPlaceholderText("Assignee")
        self.case_legal_hold = QCheckBox("Legal hold")
        update = QPushButton("Update")
        update.clicked.connect(self._update_case)
        update_row.addWidget(self.case_status)
        update_row.addWidget(self.case_update_assignee, 1)
        update_row.addWidget(self.case_legal_hold)
        update_row.addWidget(update)
        right_box.addLayout(update_row)
        note_row = QHBoxLayout()
        self.case_note = QLineEdit()
        self.case_note.setPlaceholderText("Add attributed investigation note")
        note = QPushButton("Add note")
        note.clicked.connect(self._add_case_note)
        export = QPushButton("Export sanitized")
        export.clicked.connect(self._export_case)
        note_row.addWidget(self.case_note, 1)
        note_row.addWidget(note)
        note_row.addWidget(export)
        right_box.addLayout(note_row)
        split.addWidget(right)
        split.setSizes([720, 480])
        root.addWidget(split, 1)
        return page

    def _build_hunt(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        query, box = self._panel(
            "Structured hunt",
            "No SQL or script input: one supported field, one operator, and a hard result bound.",
        )
        row = QHBoxLayout()
        self.hunt_field = QComboBox()
        for label, value in (
            ("All evidence", ""), ("Module", "module"), ("Severity", "severity"),
            ("Category", "category"), ("Activity", "activity"), ("Message", "message"),
        ):
            self.hunt_field.addItem(label, value)
        self.hunt_operator = QComboBox()
        for operator in ("contains", "eq", "prefix"):
            self.hunt_operator.addItem(operator, operator)
        self.hunt_value = QLineEdit()
        self.hunt_value.setPlaceholderText("Value (blank for all evidence)")
        self.hunt_hours = QDoubleSpinBox()
        self.hunt_hours.setRange(0.05, 8760.0)
        self.hunt_hours.setValue(24.0)
        self.hunt_hours.setSuffix(" h")
        self.hunt_limit = QSpinBox()
        self.hunt_limit.setRange(1, 1000)
        self.hunt_limit.setValue(200)
        self.hunt_run = QPushButton("Run hunt")
        self.hunt_run.clicked.connect(self._run_hunt)
        for widget in (
            self.hunt_field, self.hunt_operator, self.hunt_value,
            self.hunt_hours, self.hunt_limit, self.hunt_run,
        ):
            row.addWidget(widget, 1 if widget is self.hunt_value else 0)
        box.addLayout(row)
        root.addWidget(query)
        self.hunt_table = self._table(
            ("Time", "Severity", "Module", "Category", "Activity", "Message", "Event ID"))
        root.addWidget(self.hunt_table, 1)
        attach = QHBoxLayout()
        attach.addWidget(QLabel("Attach selected result to:"))
        self.hunt_case = QComboBox()
        attach.addWidget(self.hunt_case, 1)
        attach_button = QPushButton("Attach evidence metadata")
        attach_button.clicked.connect(self._attach_hunt_evidence)
        attach.addWidget(attach_button)
        self.hunt_status = QLabel("Ready")
        self.hunt_status.setStyleSheet("color:#8ea5bf")
        attach.addWidget(self.hunt_status)
        root.addLayout(attach)
        return page

    def _build_assets(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        header, box = self._panel(
            "Local asset map",
            "Privacy-minimized OS, Angerona module, and Python runtime SBOM inventory.",
        )
        row = QHBoxLayout()
        self.inventory_stamp = QLabel("No snapshot yet")
        row.addWidget(self.inventory_stamp)
        row.addStretch()
        collect = QPushButton("Collect inventory")
        collect.clicked.connect(self._collect_inventory)
        row.addWidget(collect)
        box.addLayout(row)
        root.addWidget(header)
        self.asset_table = self._table(
            ("Category", "Name", "Value", "Status", "Source", "Freshness", "Privacy"))
        root.addWidget(self.asset_table, 1)
        return page

    def _build_detections(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        info, box = self._panel(
            "Detection content lifecycle",
            "Packages are immutable, staged in quarantine, and cannot activate without a trusted publisher signature.",
        )
        controls = QHBoxLayout()
        stage = QPushButton("Stage package…")
        stage.clicked.connect(self._stage_detection)
        activate = QPushButton("Activate selected")
        activate.clicked.connect(self._activate_detection)
        rollback = QPushButton("Rollback selected package")
        rollback.clicked.connect(self._rollback_detection)
        controls.addWidget(stage)
        controls.addWidget(activate)
        controls.addWidget(rollback)
        controls.addStretch()
        self.detection_policy = QLabel("POLICY: TRUSTED SIGNATURE REQUIRED")
        self.detection_policy.setStyleSheet("color:#34d399;font-weight:700")
        controls.addWidget(self.detection_policy)
        box.addLayout(controls)
        root.addWidget(info)
        self.detection_table = self._table(
            ("Package", "Digest", "State", "Trusted", "Signer", "Previous"))
        root.addWidget(self.detection_table, 1)
        return page

    def _build_audit(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        header, box = self._panel(
            "Administrative audit",
            "Append-only local ledger with per-record HMAC chaining and write-once export.",
        )
        row = QHBoxLayout()
        self.audit_health = QLabel("Integrity: checking…")
        row.addWidget(self.audit_health)
        row.addStretch()
        export = QPushButton("Export append-only audit…")
        export.clicked.connect(self._export_audit)
        row.addWidget(export)
        box.addLayout(row)
        root.addWidget(header)
        self.audit_table = self._table(
            ("Sequence", "Time", "Action", "Target", "Result", "Actor", "Record ID"))
        root.addWidget(self.audit_table, 1)
        return page

    def _build_interoperability(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        heading, box = self._panel(
            "Capability coverage",
            "Evidence-backed comparison with major open defensive platforms. "
            "A shipped local foundation is never presented as a production-scale service.",
        )
        row = QHBoxLayout()
        self.parity_status = QLabel("Loading capability evidence…")
        self.parity_status.setWordWrap(True)
        row.addWidget(self.parity_status, 1)
        box.addLayout(row)
        root.addWidget(heading)
        self.parity_table = self._table(
            ("Domain", "Level", "Angerona coverage", "Reference projects", "Boundary / next gate")
        )
        root.addWidget(self.parity_table, 2)

        split = QSplitter(Qt.Horizontal)
        ingest, ingest_box = self._panel(
            "Network evidence import",
            "Import a selected local JSON/JSONL export. Files are bounded, normalized, "
            "field-minimized and never sent over the network.",
        )
        self.interop_format = QComboBox()
        for label, value in (
            ("Suricata EVE JSON", "suricata-eve"),
            ("Zeek JSON logs", "zeek-json"),
            ("OCSF JSON", "ocsf-json"),
            ("Generic defensive JSON", "generic-json"),
        ):
            self.interop_format.addItem(label, value)
        import_button = QPushButton("Import local evidence…")
        import_button.clicked.connect(self._import_security_evidence)
        ingest_box.addWidget(self.interop_format)
        ingest_box.addWidget(import_button)
        self.interop_result = QLabel("No import run in this session.")
        self.interop_result.setWordWrap(True)
        self.interop_result.setStyleSheet("color:#8ea5bf")
        ingest_box.addWidget(self.interop_result)
        ingest_box.addStretch()
        split.addWidget(ingest)

        query, query_box = self._panel(
            "Read-only endpoint snapshot",
            "Uses a known system osquery installation and fixed SELECT templates. "
            "There is no command box, arbitrary SQL, remote session or extension loading.",
        )
        self.osquery_template = QComboBox()
        for template in OSQUERY_TEMPLATES.values():
            if platform.system() in template.platforms:
                self.osquery_template.addItem(template.name, template.template_id)
        self.osquery_state = QLabel("")
        self.osquery_state.setWordWrap(True)
        self.osquery_result = QLabel("No snapshot run in this session.")
        self.osquery_result.setWordWrap(True)
        self.osquery_result.setStyleSheet("color:#8ea5bf")
        query_button = QPushButton("Run guarded snapshot")
        query_button.clicked.connect(self._run_osquery_snapshot)
        query_box.addWidget(self.osquery_template)
        query_box.addWidget(query_button)
        query_box.addWidget(self.osquery_state)
        query_box.addWidget(self.osquery_result)
        query_box.addStretch()
        split.addWidget(query)
        split.setSizes([650, 650])
        root.addWidget(split, 1)
        return page

    def _callback(self, name: str) -> None:
        callback = self.callbacks.get(name)
        if callback is not None:
            callback()

    def _open_metric(self, key: str) -> None:
        destination = {
            "cases": 1, "evidence": 2, "audit": 6, "assets": 3, "detections": 4,
        }.get(key, 0)
        self.tabs.setCurrentIndex(destination)

    def _run_task(self, name: str, function: Callable[[], Any]) -> None:
        if name in self._tasks:
            return
        self._tasks.add(name)
        self._task_loading[name] = begin_loading(
            f"Retrieving {name.replace('-', ' ')} information…"
        )
        self.busy.setText("Working locally: " + ", ".join(sorted(self._tasks)))

        def work() -> None:
            try:
                result = function()
                error = ""
            except Exception as exc:  # surfaced on GUI thread
                result = None
                error = f"{type(exc).__name__}: {exc}"
            self.task_done.emit(name, result, error)

        threading.Thread(target=work, name=f"angerona-soc-{name}", daemon=True).start()

    def _finish_task(self, name: str, result: object, error: str) -> None:
        self._tasks.discard(name)
        finish_loading(self._task_loading.pop(name, None))
        self.busy.setText(
            "Working locally: " + ", ".join(sorted(self._tasks)) if self._tasks else "")
        if error:
            QMessageBox.warning(self, "Local SOC", error)
            return
        if name == "hunt":
            self._show_hunt_result(result)
        elif name == "inventory":
            self._refresh_assets(result)
        elif name == "interop-import":
            self.interop_result.setText(
                f"Imported {result.imported} · duplicates {result.duplicates} · "
                f"skipped {result.skipped} · scanned {result.scanned}" +
                (" · bounded at the import limit" if result.truncated else "")
            )
        elif name == "osquery-snapshot":
            self.osquery_result.setText(
                f"Snapshot retained: {result['imported']} new row(s), "
                f"{result['duplicates']} duplicate(s)."
            )
        self.refresh_all()

    def refresh_all(self) -> None:
        try:
            summary = self.service.summary()
            statuses = summary["case_status"]
            total = int(summary["cases"])
            open_cases = int(statuses["open"] + statuses["investigating"])
            closed = int(statuses["resolved"] + statuses["closed"])
            self.deck.cards["cases"].set_metric(
                open_cases, closed / max(total, 1), f"{closed} completed · {total} total")
            evidence = int(summary["evidence_records"])
            self.deck.cards["evidence"].set_metric(
                evidence, min(evidence / 1000.0, 1.0), "bounded normalized records")
            audit = summary["audit"]
            audit_ok = bool(audit.get("ok", False))
            self.deck.cards["audit"].set_metric(
                "PASS" if audit_ok else "CHECK", 1.0 if audit_ok else 0.1,
                f"{audit.get('records', 0)} chained actions")
            assets = int(summary["inventory_records"])
            self.deck.cards["assets"].set_metric(
                assets, min(assets / 500.0, 1.0),
                "privacy-minimized local fields")
            detections = self.service.detection_inventory()
            active = sum(item["state"] == "active" and item["trusted"] for item in detections)
            self.deck.cards["detections"].set_metric(
                active, active / max(len(detections), 1),
                f"{len(detections)} retained · signed-only active")
            self.overview_note.setText(
                f"Current local operations picture: {open_cases} active case(s), "
                f"{evidence} normalized evidence record(s), {assets} inventory record(s), "
                f"and {active} active trusted detection package(s). Audit chain: "
                f"{'verified' if audit_ok else 'requires attention'}.")
            self.audit_health.setText(
                "Integrity: VERIFIED" if audit_ok else "Integrity: CHECK REQUIRED")
            self.audit_health.setStyleSheet(
                "color:#34d399;font-weight:700" if audit_ok
                else "color:#fb7185;font-weight:700")
            self._refresh_cases()
            self._refresh_assets()
            self._refresh_detections()
            self._refresh_parity()
            self._refresh_audit()
        except Exception as exc:
            self.boundary.setText(f"LOCAL SOC UNAVAILABLE · {exc}")
            self.boundary.setStyleSheet("color:#fb7185")

    def _refresh_parity(self) -> None:
        report = self.service.capability_parity()
        rows = tuple(report["rows"])
        self.parity_table.setRowCount(len(rows))
        for row_index, record in enumerate(rows):
            values = (
                record["domain"], str(record["level"]).replace("-", " ").title(),
                record["angerona"], ", ".join(record["reference_projects"]),
                record["boundary"],
            )
            for column, value in enumerate(values):
                self.parity_table.setItem(
                    row_index, column, QTableWidgetItem(str(value)))
        counts = report["counts"]
        covered = counts["operational"] + counts["integrated"]
        self.parity_status.setText(
            f"{covered} of {report['domains']} domains are directly operational or "
            f"integrated locally; {counts['preview']} preview, {counts['foundation']} "
            f"foundation, {counts['external-gate']} infrastructure gate. "
            "No unqualified enterprise-parity claim is made."
        )
        osquery = discover_osquery()
        self.osquery_state.setText(
            f"Ready: {osquery.name} from a known system installation."
            if osquery else
            "Optional osqueryi was not found in a known system installation. "
            "Angerona's native structured hunts remain available."
        )

    def _import_security_evidence(self) -> None:
        name, _ = QFileDialog.getOpenFileName(
            self, "Import local defensive evidence", "",
            "JSON / JSON Lines (*.json *.jsonl);;All files (*)",
        )
        if not name:
            return
        format_name = str(self.interop_format.currentData())
        self._run_task(
            "interop-import",
            lambda: self.service.import_security_evidence(Path(name), format_name),
        )

    def _run_osquery_snapshot(self) -> None:
        template_id = str(self.osquery_template.currentData() or "")
        if not template_id:
            QMessageBox.information(
                self, "osquery integration", "No template is available on this platform.")
            return
        self._run_task(
            "osquery-snapshot",
            lambda: self.service.run_osquery_snapshot(template_id),
        )

    def _selected_case_id(self) -> str:
        row = self.case_table.currentRow()
        if row < 0:
            return ""
        item = self.case_table.item(row, 0)
        return item.data(Qt.UserRole) if item else ""

    def _refresh_cases(self) -> None:
        selected = self._selected_case_id()
        status = self.case_filter.currentData() if hasattr(self, "case_filter") else ""
        cases = self.service.cases.list_cases(status=status or None)
        evidence_counts = self.service.cases.evidence_counts()
        self.case_table.setRowCount(len(cases))
        self.hunt_case.clear()
        for row, case in enumerate(cases):
            evidence_count = evidence_counts.get(case.case_id, 0)
            values = (
                case.case_id[-10:], case.title, case.status, case.assignee or "—",
                _stamp(case.updated_at), str(evidence_count),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, case.case_id)
                self.case_table.setItem(row, column, item)
            self.hunt_case.addItem(f"{case.title}  [{case.status}]", case.case_id)
            if case.case_id == selected:
                self.case_table.selectRow(row)
        if cases and self.case_table.currentRow() < 0:
            self.case_table.selectRow(0)

    def _create_case(self) -> None:
        title = self.case_title.text().strip()
        if not title:
            QMessageBox.information(self, "New case", "Enter a case title.")
            return
        tags = tuple(tag.strip() for tag in self.case_tags.text().split(",") if tag.strip())
        try:
            self.service.create_case(
                title, assignee=self.case_assignee.text().strip(), tags=tags)
            self.case_title.clear()
            self.case_tags.clear()
            self.refresh_all()
        except Exception as exc:
            QMessageBox.warning(self, "New case", str(exc))

    def _show_case_detail(self) -> None:
        case_id = self._selected_case_id()
        if not case_id:
            self.case_detail.clear()
            return
        try:
            case = self.service.cases.get_case(case_id)
            timeline = self.service.cases.timeline(case_id)
            evidence = self.service.cases.evidence(case_id)
            custody_ok = all(
                self.service.cases.verify_custody(item.evidence_id) for item in evidence)
            lines = [
                f"{case.title}",
                f"ID: {case.case_id}",
                f"Status: {case.status}  ·  Assignee: {case.assignee or 'unassigned'}",
                f"Tags: {', '.join(case.tags) or 'none'}  ·  Legal hold: {'yes' if case.legal_hold else 'no'}",
                f"Evidence custody: {'VERIFIED' if custody_ok else 'CHECK REQUIRED'}",
                "",
                "TIMELINE",
            ]
            lines.extend(
                f"{_stamp(item.timestamp)}  [{item.kind}] {item.actor}: {item.text}"
                for item in timeline
            )
            lines.append("")
            lines.append("EVIDENCE METADATA")
            lines.extend(
                f"{item.display_name} · {item.sha256[:16]}… · {item.size} bytes · {item.privacy_class}"
                for item in evidence
            )
            self.case_detail.setPlainText("\n".join(lines))
            self.case_status.setCurrentText(case.status.title())
            self.case_update_assignee.setText(case.assignee)
            self.case_legal_hold.setChecked(case.legal_hold)
        except Exception as exc:
            self.case_detail.setPlainText(str(exc))

    def _update_case(self) -> None:
        case_id = self._selected_case_id()
        if not case_id:
            return
        try:
            self.service.update_case(
                case_id,
                status=self.case_status.currentText().lower(),
                assignee=self.case_update_assignee.text().strip(),
                legal_hold=self.case_legal_hold.isChecked(),
            )
            self.refresh_all()
        except Exception as exc:
            QMessageBox.warning(self, "Update case", str(exc))

    def _add_case_note(self) -> None:
        case_id = self._selected_case_id()
        note = self.case_note.text().strip()
        if not case_id or not note:
            return
        try:
            self.service.add_case_comment(case_id, note)
            self.case_note.clear()
            self.refresh_all()
        except Exception as exc:
            QMessageBox.warning(self, "Case note", str(exc))

    def _export_case(self) -> None:
        case_id = self._selected_case_id()
        if not case_id:
            return
        name, _ = QFileDialog.getSaveFileName(
            self, "Export sanitized case", f"{case_id}.json", "JSON (*.json)")
        if not name:
            return
        try:
            path = self.service.export_case(case_id, Path(name))
            QMessageBox.information(self, "Case exported", f"Saved sanitized case to:\n{path}")
        except Exception as exc:
            QMessageBox.warning(self, "Case export", str(exc))

    def _run_hunt(self) -> None:
        field = str(self.hunt_field.currentData() or "")
        value: Any = self.hunt_value.text().strip()
        if field == "severity" and value:
            try:
                value = int(value)
            except ValueError:
                QMessageBox.information(self, "Hunt", "Severity must be a number from 0 to 4.")
                return
        self._run_task(
            "hunt",
            lambda: self.service.hunt(
                field=field or None,
                operator=str(self.hunt_operator.currentData()),
                value=value,
                hours=self.hunt_hours.value(),
                limit=self.hunt_limit.value(),
            ),
        )

    def _show_hunt_result(self, result: Any) -> None:
        self._hunt_rows = tuple(result.evidence)
        self.hunt_table.setRowCount(len(self._hunt_rows))
        for row, evidence in enumerate(self._hunt_rows):
            values = (
                _stamp(evidence.observed_at),
                _SEVERITY[int(evidence.severity)],
                evidence.module,
                evidence.category,
                evidence.activity,
                evidence.message,
                evidence.event_id,
            )
            for column, value in enumerate(values):
                self.hunt_table.setItem(row, column, QTableWidgetItem(str(value)))
        self.hunt_status.setText(
            f"{len(self._hunt_rows)} match(es) · scanned {result.scanned} · "
            f"{result.elapsed_ms:.1f} ms" + (" · bounded" if result.truncated else ""))

    def _attach_hunt_evidence(self) -> None:
        row = self.hunt_table.currentRow()
        case_id = str(self.hunt_case.currentData() or "")
        if row < 0 or row >= len(self._hunt_rows) or not case_id:
            QMessageBox.information(self, "Attach evidence", "Select a result and a case.")
            return
        try:
            self.service.attach_evidence(case_id, self._hunt_rows[row])
            self.refresh_all()
        except Exception as exc:
            QMessageBox.warning(self, "Attach evidence", str(exc))

    def _collect_inventory(self) -> None:
        self._run_task("inventory", self.service.collect_inventory)

    def _refresh_assets(self, snapshot: Any | None = None) -> None:
        snapshot = snapshot or self.service.inventory_store.load()
        records = tuple(snapshot.records) if snapshot else ()
        self.asset_table.setRowCount(len(records))
        now = datetime.now().timestamp()
        for row, record in enumerate(records):
            values = (
                record.category.value,
                record.name,
                _plain(record.value),
                record.status.value,
                record.source,
                "fresh" if record.is_fresh(now=now) else "stale",
                record.privacy.value,
            )
            for column, value in enumerate(values):
                self.asset_table.setItem(row, column, QTableWidgetItem(value))
        self.inventory_stamp.setText(
            f"Snapshot: {_stamp(snapshot.created_at)} · {len(records)} record(s)"
            if snapshot else "No snapshot yet")

    def _stage_detection(self) -> None:
        name, _ = QFileDialog.getOpenFileName(
            self, "Stage detection package", "", "JSON (*.json)")
        if not name:
            return
        package = Path(name)
        candidates = (
            package.with_suffix(package.suffix + ".sig.json"),
            package.with_name(package.stem + ".sig.json"),
        )
        signature = next((candidate for candidate in candidates if candidate.is_file()), None)
        report = self.service.stage_detection(package, signature=signature)
        message = report.state if report.ok else "\n".join(report.errors)
        QMessageBox.information(self, "Detection stage", message)
        self.refresh_all()

    def _selected_detection(self) -> tuple[str, str]:
        row = self.detection_table.currentRow()
        if row < 0:
            return "", ""
        package = self.detection_table.item(row, 0)
        digest = self.detection_table.item(row, 1)
        return (package.text() if package else "", digest.text() if digest else "")

    def _activate_detection(self) -> None:
        package, digest = self._selected_detection()
        if not package or not digest:
            return
        answer = QMessageBox.question(
            self, "Activate detection",
            "Activate this immutable detection version? The trusted publisher "
            "signature will be checked again.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        report = self.service.activate_detection(package, digest)
        QMessageBox.information(
            self, "Detection activation",
            report.state if report.ok else "\n".join(report.errors))
        self.refresh_all()

    def _rollback_detection(self) -> None:
        package, _ = self._selected_detection()
        if not package:
            return
        report = self.service.rollback_detection(package)
        QMessageBox.information(
            self, "Detection rollback",
            report.state if report.ok else "\n".join(report.errors))
        self.refresh_all()

    def _refresh_detections(self) -> None:
        records = self.service.detection_inventory()
        self.detection_table.setRowCount(len(records))
        for row, record in enumerate(records):
            values = (
                record["package_id"], record["digest"], record["state"],
                "yes" if record["trusted"] else "no",
                record["signer"] or "—", record["previous_digest"] or "—",
            )
            for column, value in enumerate(values):
                self.detection_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _refresh_audit(self) -> None:
        records = self.service.audit_records(limit=500)
        self.audit_table.setRowCount(len(records))
        for row, record in enumerate(records):
            entry = record.entry
            values = (
                record.sequence, _stamp(entry.timestamp), entry.action, entry.target,
                entry.result, entry.actor_id, entry.record_id,
            )
            for column, value in enumerate(values):
                self.audit_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _export_audit(self) -> None:
        name, _ = QFileDialog.getSaveFileName(
            self, "Export append-only audit", "angerona-local-soc-audit.jsonl",
            "JSON Lines (*.jsonl)")
        if not name:
            return
        try:
            path = self.service.export_audit(Path(name))
            QMessageBox.information(self, "Audit exported", f"Saved to:\n{path}")
        except Exception as exc:
            QMessageBox.warning(self, "Audit export", str(exc))

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if motion_allowed(getattr(self.service, "config", None)) and not self.deck._timer.isActive():
            self.deck._timer.start()
        QTimer.singleShot(0, self.refresh_all)

    def closeEvent(self, event) -> None:
        self.deck.stop()
        super().closeEvent(event)


__all__ = ["FlowMetricDeck", "OperationsCenterDialog", "RadialMetricCard"]
