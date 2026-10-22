"""SpywareGuard's bounded, local Qt view; module commands enqueue worker jobs.

Opening the page only reads an in-memory snapshot. Reports and sandbox drills
require explicit operator actions. All evidence is rendered as plain text.
"""
from __future__ import annotations

import json
import math
import time
from collections.abc import Mapping
from datetime import datetime
from urllib.parse import urlsplit

from PySide6.QtCore import Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QScrollArea, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.spyware_catalog import CATALOG_SCOPE, SPYWARE_PROFILES
from angerona.core.spyware_news import (
    MAX_NEWS_AGE, MAX_NEWS_ITEMS, NEWS_SOURCE_LABELS, safe_news_article_url,
)
from angerona.gui.header_controls import motion_allowed


_ROW_LIMIT = 200
_SETTINGS = (
    ("spyware_auto_contain", "Contain on a single detection rule", True),
    ("spyware_network_enabled", "Allow HTTPS research report ingestion", False),
    ("spyware_memory_enabled", "Enable optional process memory inspection", False),
    ("spyware_beacon_enabled", "Enable Hail Mary emergency beacon", False),
    ("spyware_beacon_channel", "Use the configured outbound notification channel", True),
    ("spyware_beacon_signal", "Use the configured authorized Signal destination", False),
)


def _text(value, limit: int = 700) -> str:
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return str(value if value is not None else "").replace("\x00", "")[:limit]


def _time_text(value) -> str:
    if type(value) in (int, float) and value > 0:
        try:
            return datetime.fromtimestamp(value).astimezone().strftime("%m-%d %H:%M:%S")
        except (ValueError, OverflowError, OSError):
            pass
    return _text(value)


def _details_text(value, limit=16_000) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)[:limit]
    return _text(value, limit)


def _label(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def _table(headers: tuple[str, ...], widths: tuple[int, ...], *, stretch: int) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    table.horizontalHeader().setStretchLastSection(False)
    for column, width in enumerate(widths):
        table.setColumnWidth(column, width)
    table.horizontalHeader().setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    table.setMinimumHeight(90)
    table.setMinimumWidth(0)
    table.setWordWrap(False)
    return table


def _scroll(widget: QWidget) -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.Shape.NoFrame)
    scroll.setWidget(widget)
    return scroll


class _NewsSpinner(QWidget):
    """Small refresh-only indicator with an explicit reduced-motion gate."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._step)
        self.hide()

    def _step(self):
        self._angle = (self._angle + 30) % 360
        self.update()

    def set_active(self, active: bool, animate: bool):
        self.setVisible(active)
        if active and animate:
            if not self._timer.isActive():
                self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(2, 2, -2, -2)
        painter.setPen(QPen(QColor("#334155"), 2))
        painter.drawEllipse(rect)
        painter.setPen(QPen(QColor("#38bdf8"), 2))
        painter.drawArc(rect, -self._angle * 16, 110 * 16)


class SpywareGuardPage(QWidget):
    settings_requested = Signal(str)

    def __init__(self, manager, config, bus, parent=None) -> None:
        super().__init__(parent)
        self.manager, self.config, self.bus = manager, config, bus
        self._closed = False
        self._settings_dirty = False
        self._pending_settings: dict | None = None
        self._snapshot: dict = {}
        self._table_rows: dict[QTableWidget, list[dict]] = {}
        self._lab_dialog = None
        self._news_items: list[dict] = []
        self._news_index = 0
        self._news_refreshing = False
        self._news_paused = False
        self._news_rotation_timer = QTimer(self)
        self._news_rotation_timer.setInterval(9_000)
        self._news_rotation_timer.timeout.connect(self._rotate_news)
        self._news_scroll_timer = QTimer(self)
        self._news_scroll_timer.setInterval(100)
        self._news_scroll_timer.timeout.connect(self._scroll_news)
        self._timer = QTimer(self)
        self._timer.setInterval(3_000)
        self._timer.timeout.connect(self.refresh)
        timer = self._timer
        self.destroyed.connect(lambda *_args: timer.stop())

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)
        header = QHBoxLayout()
        title = _label("SPYWAREGUARD · Surveillanceware & Zero-Day Defense")
        title.setObjectName("SectionTitle")
        header.addWidget(title, 1)
        self.scan_button = QPushButton("Scan now")
        self.scan_button.clicked.connect(self._request_scan)
        header.addWidget(self.scan_button)
        root.addLayout(header)
        self._build_news_strip(root)
        self.status = _label("Open this tab to view local evidence and module coverage.")
        root.addWidget(self.status)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self._build_dashboard()
        self._build_settings()
        self._build_research()
        self._build_sandbox()
        self._build_guide()
        self._update_availability()

    def _build_news_strip(self, root) -> None:
        self.news_strip = QWidget()
        self.news_strip.setObjectName("SpywareNewsStrip")
        row = QHBoxLayout(self.news_strip)
        row.setContentsMargins(3, 2, 3, 2)
        row.setSpacing(7)
        self.news_spinner = _NewsSpinner(self.news_strip)
        row.addWidget(self.news_spinner)
        self.news_badge = _label("INTEL")
        self.news_badge.setWordWrap(False)
        self.news_badge.setStyleSheet("color:#38bdf8; font-weight:700; font-size:10px;")
        row.addWidget(self.news_badge)
        self.news_scroll = QScrollArea()
        self.news_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.news_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.news_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.news_scroll.setMinimumWidth(0)
        self.news_scroll.setFixedHeight(25)
        self.news_headline = QPushButton("News offline · enable research network access in Policy / Beacon.")
        self.news_headline.setStyleSheet("padding:2px; border:0; background:transparent; text-align:left;")
        self.news_headline.setCursor(Qt.CursorShape.PointingHandCursor)
        self.news_headline.clicked.connect(self._open_news_article)
        self.news_headline.setEnabled(False)
        self.news_scroll.setWidget(self.news_headline)
        row.addWidget(self.news_scroll, 1)
        self.news_source_button = QPushButton("")
        self.news_source_button.setStyleSheet("padding:2px; border:0; color:#38bdf8;")
        self.news_source_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.news_source_button.clicked.connect(self._open_news_article)
        self.news_source_button.setVisible(False)
        row.addWidget(self.news_source_button)
        self.news_pause_button = QPushButton("Pause")
        self.news_pause_button.setCheckable(True)
        self.news_pause_button.setToolTip("Pause headline scrolling, rotation, and the refresh animation.")
        self.news_pause_button.toggled.connect(self._pause_news)
        self.news_pause_button.setEnabled(False)
        self.news_pause_button.setStyleSheet("padding:3px 7px;")
        row.addWidget(self.news_pause_button)
        self.news_refresh_button = QPushButton("Refresh")
        self.news_refresh_button.setToolTip("Queue official RSS/Atom headline refresh; requires network ingestion.")
        self.news_refresh_button.setEnabled(False)
        self.news_refresh_button.setStyleSheet("padding:3px 7px;")
        self.news_refresh_button.clicked.connect(self._request_news_refresh)
        row.addWidget(self.news_refresh_button)
        root.addWidget(self.news_strip)

    def _news_message(self, message: str) -> None:
        self.news_badge.setText("INTEL")
        self.news_headline.setText(message.replace("&", "&&"))
        self.news_headline.setToolTip(message)
        self.news_headline.setAccessibleName(message)
        self.news_headline.setEnabled(False)
        self.news_headline.adjustSize()
        self.news_source_button.setVisible(False)
        self.news_scroll.horizontalScrollBar().setValue(0)

    def _update_news(self, snapshot: dict) -> None:
        settings = snapshot.get("settings") or {}
        enabled = settings.get("spyware_network_enabled", getattr(self.config, "spyware_network_enabled", False)) is True
        status = snapshot.get("news_status") or {}
        if not isinstance(status, dict):
            status = {}
        state = str(status.get("state", ""))
        self._news_refreshing = enabled and (status.get("refreshing") is True or state in {"refreshing", "queued", "updating"})
        self.news_refresh_button.setEnabled(enabled and self._module() is not None and not self._news_refreshing)
        previous_url = self._news_items[self._news_index]["url"] if self._news_items else None
        items = []
        now = time.time()
        raw_items = snapshot.get("news", [])
        seen = set()
        if enabled and isinstance(raw_items, (list, tuple)):
            for item in raw_items[:MAX_NEWS_ITEMS]:
                if not isinstance(item, dict):
                    continue
                stamp, verified = item.get("published"), item.get("verified_at")
                if (type(stamp) not in (int, float) or type(verified) not in (int, float)
                        or not math.isfinite(stamp) or not math.isfinite(verified)
                        or not 0 < stamp <= verified <= now or now - stamp > MAX_NEWS_AGE):
                    continue
                try:
                    url = safe_news_article_url(item.get("url"), item.get("source"))
                except (ValueError, TypeError, UnicodeError):
                    continue
                title = _text(item.get("title"), 260).strip()
                if not title or url in seen:
                    continue
                seen.add(url)
                items.append(dict(item, title=title, url=url))
        items.sort(key=lambda item: -item["published"])
        changed = items != self._news_items
        self._news_items = items
        self._news_index = next((i for i, item in enumerate(items) if item["url"] == previous_url), 0)
        self.news_pause_button.setEnabled(bool(items) or self._news_refreshing)
        if items:
            if changed:
                self._show_news_headline()
        elif not enabled:
            self._news_message("News offline · enable research network access in Policy / Beacon.")
        elif self._news_refreshing:
            self._news_message("Refreshing official spyware and exploit research headlines…")
        elif state in {"failed", "error"}:
            self._news_message("News unavailable · the latest official-feed refresh failed.")
        else:
            self._news_message("No verified spyware or exploit headlines from the last 30 days.")
        self.news_strip.setToolTip(
            "Official research headlines only. Article publication dates determine freshness; "
            "news never activates detection or response rules. " + _text(status.get("error", ""), 200)
        )
        self._sync_news_motion()

    def _show_news_headline(self) -> None:
        if not self._news_items:
            return
        item = self._news_items[self._news_index]
        source = NEWS_SOURCE_LABELS[item["source"]]
        date = datetime.fromtimestamp(item["published"]).astimezone().strftime("%b %d")
        self.news_badge.setText(f"INTEL {self._news_index + 1}/{len(self._news_items)}")
        self.news_headline.setText(item["title"].replace("&", "&&"))
        self.news_headline.setAccessibleName(item["title"])
        self.news_headline.setToolTip(item["title"] + "\n" + item["url"])
        self.news_headline.setEnabled(True)
        self.news_headline.adjustSize()
        self.news_source_button.setText(f"{source} · {date}")
        self.news_source_button.setToolTip(f"{source}\nPublished: " + datetime.fromtimestamp(item["published"]).astimezone().isoformat() + "\n" + item["url"])
        self.news_source_button.setVisible(True)
        self.news_scroll.horizontalScrollBar().setValue(0)

    def _rotate_news(self) -> None:
        if not self._news_items:
            return
        self._news_index = (self._news_index + 1) % len(self._news_items)
        self._show_news_headline()
        self._sync_news_motion()

    def _scroll_news(self) -> None:
        bar = self.news_scroll.horizontalScrollBar()
        if bar.maximum() > 0:
            bar.setValue(0 if bar.value() >= bar.maximum() else bar.value() + 3)

    def _pause_news(self, paused: bool) -> None:
        self._news_paused = paused
        self.news_pause_button.setText("Resume" if paused else "Pause")
        self._sync_news_motion()

    def _sync_news_motion(self) -> None:
        visible = not self._closed and self.isVisible()
        animate = visible and not self._news_paused and motion_allowed(self.config)
        if animate and len(self._news_items) > 1:
            if not self._news_rotation_timer.isActive():
                self._news_rotation_timer.start()
        else:
            self._news_rotation_timer.stop()
        if animate and self._news_items and self.news_scroll.horizontalScrollBar().maximum() > 0:
            if not self._news_scroll_timer.isActive():
                self._news_scroll_timer.start()
        else:
            self._news_scroll_timer.stop()
        self.news_spinner.set_active(self._news_refreshing, animate)

    def _request_news_refresh(self) -> None:
        settings = self._snapshot.get("settings") or {}
        if settings.get("spyware_network_enabled", getattr(self.config, "spyware_network_enabled", False)) is not True:
            self.status.setText("Enable research network access in Policy / Beacon before refreshing news.")
            return
        if self._command("request_news_refresh"):
            self._news_refreshing = True
            self.news_refresh_button.setEnabled(False)
            self.news_pause_button.setEnabled(True)
            if not self._news_items:
                self._news_message("Official research headline refresh queued…")
            self._sync_news_motion()
            self.status.setText("Official news refresh queued. Headlines remain advisory research.")
        else:
            self.status.setText("News refresh was not queued. Enable network ingestion and check pending work.")

    def _open_news_article(self) -> None:
        if not self._news_items:
            return
        item = self._news_items[self._news_index]
        try:
            url = safe_news_article_url(item["url"], item["source"])
        except (ValueError, TypeError, UnicodeError):
            return
        QDesktopServices.openUrl(QUrl(url))

    def _module(self):
        modules = getattr(self.manager, "modules", {})
        return modules.get("SpywareGuard") if isinstance(modules, Mapping) else None

    def _build_dashboard(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.stats = _label("Hits: 0   ·   Containment records: 0   ·   Approved indicators: 0")
        layout.addWidget(self.stats)
        self.evidence_tabs = QTabWidget()
        self.hits_table = _table(("Time", "Rule", "Process / artifact", "Severity"), (150, 210, 170, 90), stretch=2)
        self.containments_table = _table(("Time", "Target", "Outcome", "Details"), (150, 170, 110, 200), stretch=3)
        self.evidence_tabs.addTab(self.hits_table, "Recent hits")
        self.evidence_tabs.addTab(self.containments_table, "Isolations / response")
        self.coverage = QPlainTextEdit()
        self.coverage.setReadOnly(True)
        self.coverage.setPlaceholderText("Module-reported coverage and limitations appear here.")
        self.evidence_tabs.addTab(self.coverage, "Coverage")
        layout.addWidget(self.evidence_tabs, 3)
        self.evidence_detail = QPlainTextEdit()
        self.evidence_detail.setReadOnly(True)
        self.evidence_detail.setMaximumHeight(130)
        self.evidence_detail.setPlaceholderText("Select a hit or response to inspect its evidence.")
        layout.addWidget(self.evidence_detail, 1)
        for table in (self.hits_table, self.containments_table):
            table.itemSelectionChanged.connect(lambda t=table: self._show_evidence(t))
        self.tabs.addTab(page, "Dashboard")

    def _build_settings(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_label(
            "Single-rule response: each eligible local detection immediately requests containment "
            "when enabled. A requested, failed, or skipped response is shown separately from a "
            "verified isolation. A native finding without a bound process, file, or remote peer "
            "requests host isolation. Heuristics can produce false positives; core system process "
            "protections and process identity checks still apply."
        ))
        self.setting_checks: dict[str, QCheckBox] = {}
        for name, title, default in _SETTINGS:
            check = QCheckBox(title)
            check.setChecked(bool(getattr(self.config, name, default)))
            check.toggled.connect(self._mark_settings_dirty)
            self.setting_checks[name] = check
            layout.addWidget(check)
        layout.addWidget(_label(
            "Memory inspection may require additional OS permissions and reports inaccessible "
            "processes. Research ingestion uses outbound HTTPS only when enabled. Telemetry "
            "coverage depends on installed producers; see Dashboard → Coverage."
        ))
        beacon = QGroupBox("Hail Mary · authorized emergency destination")
        beacon_layout = QVBoxLayout(beacon)
        self.beacon_status = _label("Beacon status appears when the module is available.")
        beacon_layout.addWidget(self.beacon_status)
        beacon_layout.addWidget(_label(
            "When enabled and a destination is configured, emergency delivery sends bounded "
            "incident metadata through the selected existing channel or Signal bridge. "
            "Credentials, memory contents, and files are excluded. Delivery is best effort: "
            "loss of power, network, or all trusted processes can prevent a beacon."
        ))
        destinations = QHBoxLayout()
        channel = QPushButton("Configure notification channel…")
        channel.clicked.connect(lambda: self.settings_requested.emit("Integrations"))
        signal = QPushButton("Configure Signal destination…")
        signal.clicked.connect(lambda: self.settings_requested.emit("Mobile Integration"))
        destinations.addWidget(channel)
        destinations.addWidget(signal)
        beacon_layout.addLayout(destinations)
        layout.addWidget(beacon)
        self.save_button = QPushButton("Apply SpywareGuard settings")
        self.save_button.clicked.connect(self._save_settings)
        layout.addWidget(self.save_button)
        layout.addStretch()
        self.tabs.addTab(_scroll(page), "Policy / Beacon")

    def _build_research(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_label(
            "Add a public HTTPS research URL, then queue a fetch. Parsing runs on the module "
            "worker. Extracted indicators retain source provenance and require review before "
            "activation. Downloaded narratives are data; they cannot install executable rules."
        ))
        url_row = QHBoxLayout()
        self.report_url = QLineEdit()
        self.report_url.setMaxLength(2_048)
        self.report_url.setPlaceholderText("https://research.example/report")
        self.ingest_button = QPushButton("Fetch & extract")
        self.ingest_button.clicked.connect(self._queue_report)
        url_row.addWidget(self.report_url, 1)
        url_row.addWidget(self.ingest_button)
        layout.addLayout(url_row)
        self.research_tabs = QTabWidget()
        self.sources_table = _table(("Source URL", "State", "Updated / error"), (280, 100, 220), stretch=0)
        self.indicators_table = _table(("Type", "Value", "Review state", "Source"), (80, 200, 160, 190), stretch=1)
        self.research_tabs.addTab(self.sources_table, "Research sources")
        self.research_tabs.addTab(self.indicators_table, "Extracted indicators")
        layout.addWidget(self.research_tabs, 1)
        review = QHBoxLayout()
        self.approve_button = QPushButton("Approve selected indicator")
        self.reject_button = QPushButton("Deactivate selected indicator")
        self.approve_button.clicked.connect(lambda: self._review_indicator(True))
        self.reject_button.clicked.connect(lambda: self._review_indicator(False))
        review.addWidget(self.approve_button)
        review.addWidget(self.reject_button)
        layout.addLayout(review)
        self.export_rules_button = QPushButton("Stage YARA / Sigma / NDR candidates")
        self.export_rules_button.setToolTip("Create inactive literal rule candidates for review in the private SpywareGuard data folder.")
        self.export_rules_button.clicked.connect(self._queue_rule_export)
        layout.addWidget(self.export_rules_button)
        self.tabs.addTab(page, "Research / Rules")

    def _build_sandbox(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_label(
            "Offline detection rehearsals use synthetic telemetry. They do not execute spyware, "
            "send network traffic, terminate a real process, or emit an emergency beacon. "
            "Drill findings remain explicitly marked as simulation."
        ))
        self.sandbox_scenario = QComboBox()
        self.sandbox_scenario.addItem("DNS tunneling · high-entropy query pattern", "dns_tunnel")
        self.sandbox_scenario.addItem("Exfiltration · sudden encrypted upload", "exfiltration")
        self.sandbox_scenario.addItem("Renderer escape · unexpected child process", "renderer_escape")
        layout.addWidget(self.sandbox_scenario)
        self.sandbox_button = QPushButton("Run offline rehearsal")
        self.sandbox_button.clicked.connect(self._run_sandbox)
        layout.addWidget(self.sandbox_button)
        self.sandbox_results = QPlainTextEdit()
        self.sandbox_results.setReadOnly(True)
        self.sandbox_results.setPlaceholderText("Sandbox results appear here after an explicit rehearsal.")
        layout.addWidget(self.sandbox_results, 1)
        lab = QPushButton("Open source Analysis Lab…")
        lab.clicked.connect(self._open_analysis_lab)
        layout.addWidget(lab)
        layout.addWidget(_label(
            "Analysis Lab checks a copy of source code with the existing isolated analyzer. "
            "It is separate from the telemetry rehearsals above and requires its optional runtime."
        ))
        self.tabs.addTab(page, "Sandbox")

    def _build_guide(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_label(CATALOG_SCOPE))
        self.guide_choice = QComboBox()
        for profile in SPYWARE_PROFILES:
            self.guide_choice.addItem(profile.title, profile.key)
        self.guide_choice.currentIndexChanged.connect(self._show_guide)
        layout.addWidget(self.guide_choice)
        self.guide_detail = QPlainTextEdit()
        self.guide_detail.setReadOnly(True)
        layout.addWidget(self.guide_detail, 1)
        self.guide_source_button = QPushButton("Open primary research source in browser")
        self.guide_source_button.clicked.connect(self._open_guide_source)
        layout.addWidget(self.guide_source_button)
        self._show_guide()
        self.tabs.addTab(page, "Field Guide")

    def _show_guide(self, *_args) -> None:
        index = self.guide_choice.currentIndex()
        if 0 <= index < len(SPYWARE_PROFILES):
            self.guide_detail.setPlainText(SPYWARE_PROFILES[index].plain_text())

    def _open_guide_source(self) -> None:
        index = self.guide_choice.currentIndex()
        if 0 <= index < len(SPYWARE_PROFILES):
            QDesktopServices.openUrl(QUrl(SPYWARE_PROFILES[index].source_url))

    def _update_availability(self) -> None:
        available = self._module() is not None
        for button in (self.scan_button, self.save_button, self.ingest_button,
                       self.approve_button, self.reject_button, self.sandbox_button,
                       self.export_rules_button):
            button.setEnabled(available)
        if not available:
            self.status.setText("SpywareGuard is unavailable. Enable the module to collect evidence.")
            self.news_refresh_button.setEnabled(False)

    def _queue_rule_export(self) -> None:
        if self._command("queue_rule_export"):
            self.status.setText("Inactive rule candidates queued for staging. See Dashboard → Coverage for the private export path.")
        else:
            self.status.setText("Rule export was not queued. Check module health or pending work.")

    def _command(self, name: str, *args, **kwargs):
        module = self._module()
        action = getattr(module, name, None)
        if not callable(action):
            self.status.setText("SpywareGuard is unavailable or does not support this action.")
            return False
        try:
            return action(*args, **kwargs)
        except Exception:
            self.status.setText("SpywareGuard could not queue this action. Check module health.")
            return False

    def _request_scan(self) -> None:
        result = self._command("request_scan")
        self.status.setText("Local spyware scan queued." if result else "Scan was not queued; check module health or pending work.")

    def _mark_settings_dirty(self, *_args) -> None:
        self._settings_dirty = True
        self._pending_settings = None

    def _save_settings(self) -> None:
        settings = {name: check.isChecked() for name, check in self.setting_checks.items()}
        result = self._command("configure_settings", **settings)
        queued = result.get("queued", False) if isinstance(result, dict) else bool(result)
        if queued:
            self._pending_settings = settings
            self.status.setText("Settings queued. The next module snapshot confirms the applied policy.")
        else:
            self.status.setText("Settings were not queued. Check module health.")

    def _queue_report(self) -> None:
        url = self.report_url.text().strip()
        try:
            parsed = urlsplit(url)
            valid = (parsed.scheme.lower() == "https" and bool(parsed.hostname)
                     and not parsed.username and not parsed.password and not parsed.fragment)
        except ValueError:
            valid = False
        if not valid:
            self.status.setText("Enter a public HTTPS report URL without credentials or a fragment.")
            return
        if self._command("queue_report_url", url):
            self.status.setText("Research URL queued for validated fetching and indicator extraction.")
            self.report_url.clear()
        else:
            self.status.setText("URL was not queued. Enable network ingestion and check the URL or pending work.")

    def _review_indicator(self, approved: bool) -> None:
        rows = self._table_rows.get(self.indicators_table, [])
        row = self.indicators_table.currentRow()
        if not 0 <= row < len(rows):
            self.status.setText("Select an extracted indicator to review.")
            return
        item = rows[row]
        kind, value = item.get("kind", item.get("type", "")), item.get("value", "")
        if self._command("review_indicator", str(kind), str(value), approved=approved):
            self.status.setText("Indicator review queued; applied state will appear in the next snapshot.")
        else:
            self.status.setText("Indicator review was not queued. Check module health.")

    def _run_sandbox(self) -> None:
        scenario = self.sandbox_scenario.currentData()
        if self._command("run_sandbox", scenario):
            self.status.setText("Offline telemetry rehearsal queued. No real containment is requested.")
        else:
            self.status.setText("Rehearsal was not queued. Check module health.")

    def _open_analysis_lab(self) -> None:
        from PySide6.QtWidgets import QDialog
        from angerona.gui.analysis_lab import AnalysisLabPanel

        if self._lab_dialog is None:
            self._lab_dialog = QDialog(self)
            self._lab_dialog.setWindowTitle("SpywareGuard · Source Analysis Lab")
            self._lab_dialog.resize(900, 620)
            layout = QVBoxLayout(self._lab_dialog)
            layout.addWidget(AnalysisLabPanel(self._lab_dialog))
        self._lab_dialog.show()
        self._lab_dialog.raise_()

    def refresh(self) -> None:
        if self._closed or not self.isVisible():
            return
        self._update_availability()
        module = self._module()
        if module is None:
            return
        try:
            snapshot = module.dashboard_snapshot()
        except Exception:
            self.status.setText("SpywareGuard snapshot unavailable; the previous view is retained.")
            return
        if not isinstance(snapshot, dict):
            return
        self._snapshot = snapshot
        self._update_news(snapshot)
        hits = self._rows(snapshot.get("hits"))
        containments = self._rows(snapshot.get("containments"))
        indicators = self._rows(snapshot.get("indicators"))
        sources = self._rows(snapshot.get("sources"))
        stats = snapshot.get("stats") or {}
        if not isinstance(stats, dict):
            stats = {}
        self.stats.setText(
            f"Hits: {_text(stats.get('findings', stats.get('hits', len(hits))), 30)}   ·   "
            f"Containment records: {_text(stats.get('containments', len(containments)), 30)}   ·   "
            f"Approved indicators: {sum(bool(row.get('approved')) for row in indicators)}"
        )
        self._fill(self.hits_table, hits, (
            ("timestamp", "ts", "time"), ("rule", "rule_id", "message"),
            ("process_name", "path", "target", "process", "pid"), ("severity", "level"),
        ))
        self._fill(self.containments_table, containments, (
            ("timestamp", "ts", "time", "created_at"), ("target", "targets", "path", "pid"),
            ("status", "outcome", "state"), ("reason", "details", "actions", "action", "error"),
        ))
        self._fill(self.sources_table, sources, (
            ("url", "source"), ("status", "state"), ("error", "updated", "timestamp", "fetched_at", "ts"),
        ))
        self._fill(self.indicators_table, indicators, (
            ("kind", "type"), ("value",), ("approved",), ("source_url", "source"),
        ))
        coverage = dict(snapshot.get("coverage") or {})
        if snapshot.get("encrypted_evidence"):
            coverage["encrypted_evidence"] = snapshot["encrypted_evidence"]
        self.coverage.setPlainText(_details_text(coverage))
        beacon = snapshot.get("beacon") or {}
        self.beacon_status.setText(_text(beacon, 2_000))
        sandbox = snapshot.get("sandbox", snapshot.get("sandbox_results", []))
        if sandbox:
            self.sandbox_results.setPlainText(_details_text(sandbox))
        settings = snapshot.get("settings")
        if isinstance(settings, dict):
            if self._pending_settings and all(settings.get(k) == v for k, v in self._pending_settings.items()):
                self._settings_dirty = False
                self._pending_settings = None
                self.status.setText("SpywareGuard settings applied.")
            if not self._settings_dirty:
                for name, check in self.setting_checks.items():
                    if name in settings:
                        previous = check.blockSignals(True)
                        check.setChecked(bool(settings[name]))
                        check.blockSignals(previous)
        state = _text(snapshot.get("status", getattr(module, "status", "available")), 140)
        if not self._settings_dirty and not self._pending_settings:
            self.status.setText(f"SpywareGuard: {state}. Showing the most recent { _ROW_LIMIT } records per view.")

    @staticmethod
    def _rows(value) -> list[dict]:
        if not isinstance(value, (list, tuple)):
            return []
        return [row for row in value[:_ROW_LIMIT] if isinstance(row, dict)]

    def _fill(self, table: QTableWidget, rows: list[dict], columns) -> None:
        # Retain selection by its complete bounded evidence record, not row index.
        previous_rows = self._table_rows.get(table, [])
        selected = table.currentRow()
        previous = previous_rows[selected] if 0 <= selected < len(previous_rows) else None
        table.blockSignals(True)
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(len(rows))
            self._table_rows[table] = rows
            for row_index, row in enumerate(rows):
                for column, keys in enumerate(columns):
                    value = next((row[key] for key in keys if row.get(key) is not None), "")
                    if keys == ("approved",):
                        value = "Approved" if value else "Inactive / review required"
                    item = table.item(row_index, column)
                    rendered = _time_text(value) if keys[0] == "timestamp" else _text(value)
                    if item is None:
                        item = QTableWidgetItem(rendered)
                        table.setItem(row_index, column, item)
                    elif item.text() != rendered:
                        item.setText(rendered)
                    item.setToolTip(rendered)
            if previous in rows:
                table.selectRow(rows.index(previous))
            elif previous is not None:
                table.clearSelection()
                table.setCurrentItem(None)
        finally:
            table.setUpdatesEnabled(True)
            table.blockSignals(False)

    def _show_evidence(self, table: QTableWidget) -> None:
        rows = self._table_rows.get(table, [])
        row = table.currentRow()
        if 0 <= row < len(rows):
            self.evidence_detail.setPlainText(json.dumps(rows[row], indent=2, ensure_ascii=False, default=str)[:16_000])

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        if not self._closed:
            self.refresh()
            self._timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        self._news_rotation_timer.stop()
        self._news_scroll_timer.stop()
        self.news_spinner.set_active(self._news_refreshing, False)
        super().hideEvent(event)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if hasattr(self, "news_spinner"):
            self._sync_news_motion()

    def closeEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        self._closed = True
        self._sync_news_motion()
        if self._lab_dialog is not None:
            self._lab_dialog.close()
        super().closeEvent(event)
