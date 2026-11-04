"""SpywareGuard's bounded, local Qt view; module commands enqueue worker jobs.

Opening the page only reads an in-memory snapshot. Reports and sandbox drills
require explicit operator actions. All evidence is rendered as plain text.
"""
from __future__ import annotations

import copy
import html
import json
import math
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from urllib.parse import urlsplit

from PySide6.QtCore import QEvent, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPen, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QFileDialog, QGroupBox, QHBoxLayout,
    QGridLayout, QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QScrollArea, QSizePolicy, QStyle, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from angerona.core.spyware_catalog import CATALOG_SCOPE, SPYWARE_PROFILES
from angerona.core.spyware_news import (
    MAX_NEWS_AGE, MAX_CACHED_NEWS_AGE, MAX_NEWS_ITEMS, MAX_NEWS_SUMMARY,
    NEWS_SOURCE_LABELS, REFERENCE_REVIEWED, reference_news, safe_news_article_url,
)
from shiboken6 import isValid

from angerona.gui.header_controls import motion_allowed
from angerona.gui.presentation_timer import PresentationTimer


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


def _tooltip_text(text: str) -> str:
    """Display external text literally even when Qt recognizes rich tooltips."""
    literal = text.replace("\r\n", "\n").replace("\r", "\n")
    return "<qt>" + html.escape(literal, quote=True).replace("\n", "<br>") + "</qt>"



def _time_text(value) -> str:
    if type(value) in (int, float) and value > 0:
        try:
            return datetime.fromtimestamp(value).astimezone().strftime("%m-%d %H:%M:%S")
        except (ValueError, OverflowError, OSError):
            pass
    return _text(value)


def _news_stamp(value, now):
    if (type(value) not in (int, float) or not 0 < value <= now
            or not math.isfinite(value)):
        return None
    return value


def _news_checked_text(value, now):
    stamp = _news_stamp(value, now)
    if stamp is None:
        return "not recorded"
    return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _news_age_text(value, now):
    stamp = _news_stamp(value, now)
    if stamp is None:
        return "age unavailable"
    minutes = int(now - stamp) // 60
    if minutes < 1:
        return "less than a minute ago"
    if minutes < 60:
        return f"{minutes} minute(s) ago"
    if minutes < 1440:
        return f"{minutes // 60} hour(s) ago"
    return f"{minutes // 1440} day(s) ago"


def _details_text(value, limit=16_000) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)[:limit]
    return _text(value, limit)


class _EvidenceLabel(QLabel):
    def setText(self, text):  # noqa: N802
        if self.text() != text:
            super().setText(text)


def _label(text: str = "") -> QLabel:
    label = _EvidenceLabel(text)
    label.setWordWrap(True)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    policy = label.sizePolicy()
    policy.setHorizontalPolicy(QSizePolicy.Policy.Ignored)
    policy.setHeightForWidth(True)
    label.setSizePolicy(policy)
    label.setMinimumWidth(0)
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


def _set_document_text(editor, text):
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


class _NewsSpinner(QWidget):
    """Small refresh-only indicator with an explicit reduced-motion gate."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self._angle = 0
        self._timer = PresentationTimer(self, pressure_sensitive=False, chill_sensitive=False, cosmetic=True)
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
    github_tools_requested = Signal(bool)

    def __init__(self, manager, config, bus, parent=None) -> None:
        super().__init__(parent)
        self.manager, self.config, self.bus = manager, config, bus
        self._closed = False
        self._settings_dirty = False
        self._pending_settings: dict | None = None
        self._snapshot: dict = {}
        self._table_rows: dict[QTableWidget, list[dict]] = {}
        self._table_rendered: dict[QTableWidget, tuple[tuple[str, ...], ...]] = {}
        self._plain_text_rendered: dict[QPlainTextEdit, str] = {}
        self._presentation_window = None
        self._lab_dialog = None
        self._news_dialog = None
        self._news_items: list[dict] = []
        self._news_index = 0
        self._news_refreshing = False
        self._news_paused = False
        self._tab_action_rows = []
        self._tab_action_columns = {}
        self._news_rotation_timer = PresentationTimer(self, pressure_sensitive=False, chill_sensitive=False, cosmetic=True)
        self._news_rotation_timer.setInterval(9_000)
        self._news_rotation_timer.timeout.connect(self._rotate_news)
        self._news_scroll_timer = PresentationTimer(self, pressure_sensitive=False, chill_sensitive=False, cosmetic=True)
        self._news_scroll_timer.setInterval(100)
        self._news_scroll_timer.timeout.connect(self._scroll_news)
        self._timer = PresentationTimer(self, pressure_sensitive=False, chill_sensitive=False)
        self._timer.setInterval(3_000)
        self._timer.timeout.connect(self.refresh)
        timer = self._timer
        self.destroyed.connect(lambda *_args: timer.stop())

        root = QVBoxLayout(self)
        from angerona.gui.action_progress import ActionActivities, ActionProgressView
        self._activities = ActionActivities(self)
        self._news_activity = None
        self.action_progress_view = ActionProgressView(self._activities, self, config=config)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)
        self._header_grid = QGridLayout()
        self._page_title = _label("SPYWAREGUARD · Surveillanceware & Zero-Day Defense")
        self._page_title.setObjectName("SectionTitle")
        self._header_grid.addWidget(self._page_title, 0, 0)
        self._header_grid.setColumnStretch(0, 1)
        self.scan_button = QPushButton("Spyware Scan")
        from angerona.gui.curated_tools import style_spyware_scan_button
        style_spyware_scan_button(self.scan_button)
        self.scan_button.clicked.connect(self._request_scan)
        self._header_grid.addWidget(self.scan_button, 0, 1)
        root.addLayout(self._header_grid)
        self._build_news_strip(root)
        from angerona.gui.curated_tools import SpywareScanControls
        self.priority_scan = SpywareScanControls(manager, self)
        root.addWidget(self.priority_scan)
        self.status = _label("Open this window to view local evidence and module coverage.")
        root.addWidget(self.status)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self._build_dashboard()
        self._build_definitions()
        self._build_settings()
        self._build_research()
        self._build_sandbox()
        self._build_guide()
        from angerona.gui.curated_tools import CuratedScannerWidget
        self.zero_breach = CuratedScannerWidget(manager, self)
        self.zero_breach.analysis_requested.connect(lambda: self.github_tools_requested.emit(True))
        self.tabs.addTab(_scroll(self.zero_breach), "Zero-Breach")
        self._update_availability()
        self._update_news({})
        # The top-level workspace owns a scrollable page, so readable sections
        # cannot force its outer frame beyond a scaled monitor's work area.
        if isinstance(parent, QDialog):
            from angerona.gui.window_fit import install_window_fit
            self._window_fit = install_window_fit(parent, scroll_content=True)

    def _build_news_strip(self, root) -> None:
        self.news_strip = QWidget()
        self.news_strip.setObjectName("SpywareNewsStrip")
        self.news_strip.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.news_strip.setStyleSheet(
            "QWidget#SpywareNewsStrip { border:1px solid palette(mid); "
            "border-left:3px solid #38bdf8; border-radius:6px; }"
        )
        self._news_grid = QGridLayout(self.news_strip)
        self._news_grid.setContentsMargins(9, 5, 7, 5)
        self._news_grid.setSpacing(7)
        self._news_identity = QWidget()
        identity = QHBoxLayout(self._news_identity)
        identity.setContentsMargins(0, 0, 0, 0)
        self.news_spinner = _NewsSpinner(self.news_strip)
        identity.addWidget(self.news_spinner)
        masthead = QVBoxLayout()
        masthead.setSpacing(0)
        self.news_masthead = _label("RESEARCH WIRE")
        self.news_masthead.setWordWrap(False)
        self.news_masthead.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.news_masthead.setStyleSheet("font-weight:800;")
        masthead.addWidget(self.news_masthead)
        self.news_badge = _label("INTEL")
        self.news_badge.setWordWrap(False)
        self.news_badge.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.news_badge.setStyleSheet("color:#38bdf8; font-weight:700;")
        masthead.addWidget(self.news_badge)
        identity.addLayout(masthead)
        self.news_scroll = QScrollArea()
        self.news_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.news_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.news_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.news_scroll.setMinimumWidth(0)
        self.news_headline = QPushButton("News offline · enable research network access in Policy / Beacon.")
        self.news_headline.setStyleSheet(
            "QPushButton { padding:2px; border:1px solid transparent; background:transparent; "
            "text-align:left; font-weight:700; } "
            "QPushButton:focus { border-color:palette(highlight); }"
        )
        self.news_headline.setCursor(Qt.CursorShape.PointingHandCursor)
        self.news_headline.clicked.connect(self._open_news_details)
        self.news_headline.setEnabled(False)
        self.news_scroll.setWidget(self.news_headline)
        self._news_actions = QWidget()
        self._news_action_grid = QGridLayout(self._news_actions)
        self._news_action_grid.setContentsMargins(0, 0, 0, 0)
        self._news_action_grid.setSpacing(7)
        self.news_source_button = QPushButton("")
        self.news_source_button.setStyleSheet("padding:2px; border:0; color:#38bdf8;")
        self.news_source_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.news_source_button.clicked.connect(self._open_news_article)
        self.news_source_button.setVisible(False)
        self._news_action_grid.addWidget(self.news_source_button, 0, 0)
        self.news_pause_button = QPushButton("Pause")
        self.news_pause_button.setCheckable(True)
        self.news_pause_button.setToolTip("Pause headline scrolling, rotation, and the refresh animation.")
        self.news_pause_button.toggled.connect(self._pause_news)
        self.news_pause_button.setEnabled(False)
        self.news_pause_button.setStyleSheet("padding:3px 7px;")
        self._news_action_grid.addWidget(self.news_pause_button, 0, 1)
        self.news_refresh_button = QPushButton("Refresh")
        self.news_refresh_button.setToolTip("Queue official RSS/Atom headline refresh; requires network ingestion.")
        self.news_refresh_button.setEnabled(False)
        self.news_refresh_button.setStyleSheet("padding:3px 7px;")
        self.news_refresh_button.clicked.connect(self._request_news_refresh)
        self._news_action_grid.addWidget(self.news_refresh_button, 0, 2)
        self.news_settings_button = QPushButton("News settings")
        self.news_settings_button.setToolTip("Review research network access in Policy / Beacon; no setting changes automatically.")
        self.news_settings_button.setStyleSheet("padding:3px 7px;")
        self.news_settings_button.clicked.connect(self._open_news_settings)
        self._news_action_grid.addWidget(self.news_settings_button, 0, 3)
        self._news_grid.addWidget(self._news_identity, 0, 0)
        self._news_grid.addWidget(self.news_scroll, 0, 1)
        self._news_grid.addWidget(self._news_actions, 0, 2)
        self._news_grid.setColumnStretch(1, 1)
        self.news_summary = _label()
        self._news_grid.addWidget(self.news_summary, 2, 0, 1, 3)
        footer = QHBoxLayout()
        self.news_state = _label()
        footer.addWidget(self.news_state, 1)
        self.news_feed_details = QPushButton("Feed details")
        self.news_feed_details.setCheckable(True)
        self.news_feed_details.setToolTip("Show the last feed check and status of each research source.")
        footer.addWidget(self.news_feed_details)
        self._news_grid.addLayout(footer, 3, 0, 1, 3)
        feed_details = QWidget()
        detail_layout = QVBoxLayout(feed_details)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        self.news_checks = _label()
        detail_layout.addWidget(self.news_checks)
        self.news_sources = _label()
        detail_layout.addWidget(self.news_sources)
        feed_details.hide()
        self.news_feed_details.toggled.connect(feed_details.setVisible)
        self._news_grid.addWidget(feed_details, 4, 0, 1, 3)
        self._news_grid.addWidget(self.action_progress_view, 5, 0, 1, 3)
        root.addWidget(self.news_strip)

    def _news_message(self, message: str) -> None:
        self.news_badge.setText("INTEL")
        self.news_headline.setText(message.replace("&", "&&"))
        self.news_headline.setToolTip(message)
        self.news_headline.setAccessibleName(message)
        self.news_headline.setEnabled(False)
        self.news_headline.adjustSize()
        self.news_source_button.setVisible(False)
        self.news_summary.clear()
        self.news_scroll.horizontalScrollBar().setValue(0)
        self._reflow_page()

    def _update_news(self, snapshot: dict) -> None:
        settings = snapshot.get("settings") or {}
        enabled = settings.get("spyware_network_enabled", getattr(self.config, "spyware_network_enabled", False)) is True
        status = snapshot.get("news_status") or {}
        if not isinstance(status, dict):
            status = {}
        state = str(status.get("state", ""))
        self._news_refreshing = enabled and (status.get("refreshing") is True or state in {"refreshing", "queued", "updating"})
        if not self._news_refreshing:
            self._activities.finish(self._news_activity)
            self._news_activity = None
        elif self._news_activity is not None:
            self._activities.update(self._news_activity, label="Official news: " + str(state)[:60] + "…")
        self.news_refresh_button.setEnabled(enabled and self._module() is not None and not self._news_refreshing)
        previous_url = self._news_items[self._news_index]["url"] if self._news_items else None
        items = []
        now = time.time()
        raw_items = snapshot.get("news", [])
        seen = set()
        if isinstance(raw_items, (list, tuple)):
            for item in raw_items[:MAX_NEWS_ITEMS]:
                if not isinstance(item, dict):
                    continue
                stamp, verified = item.get("published"), item.get("verified_at")
                if (type(stamp) not in (int, float) or type(verified) not in (int, float)
                        or not math.isfinite(stamp) or not math.isfinite(verified)
                        or not 0 < stamp <= verified <= now or now - stamp > MAX_CACHED_NEWS_AGE):
                    continue
                try:
                    url = safe_news_article_url(item.get("url"), item.get("source"))
                except (ValueError, TypeError, UnicodeError):
                    continue
                title = _text(item.get("title"), 260).strip()
                if not title or url in seen:
                    continue
                seen.add(url)
                items.append(dict(item, title=title, url=url, origin="cached-feed",
                                  summary=_text(item.get("summary"), MAX_NEWS_SUMMARY),
                                  stale=now - stamp > MAX_NEWS_AGE or now - verified > 3600))
        items.sort(key=lambda item: -item["published"])
        if not items:
            try:
                items = reference_news(now=now)
            except ValueError:
                items = []
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
        mode = ("Downloads disabled" if not enabled else "Refresh queued" if state == "queued" else
                "Refreshing official sources" if self._news_refreshing else
                "Research worker stopped" if state == "stopped" else
                "Waiting for the module's first refresh" if state == "awaiting-refresh" else
                "Refresh unavailable" if state in {"failed", "error", "retry-required"} else
                "Some sources unavailable" if state == "partial" else "Official-source research")
        if enabled and state == "empty":
            mode = "No recent eligible feed headlines"
        origin = (f"Bundled reference briefs · reviewed {REFERENCE_REVIEWED}; no live check" if
                  items and items[0].get("origin") == "bundled-reference" else
                  f"{len(items)} cached headlines; publication and last-check dates in details")
        self.news_state.setText(mode + " · " + origin)
        sources = status.get("sources") or {}
        source_details = "\n".join(f"{NEWS_SOURCE_LABELS.get(name, name)}: {_text(row, 220)}"
                                   for name, row in list(sources.items())[:3]) if isinstance(sources, dict) else ""
        self.news_state.setToolTip(_tooltip_text(source_details or "No automatic downloads without the research network setting."))
        self.news_strip.setToolTip(_tooltip_text(
            "Official research headlines only. Article publication dates determine freshness; "
            "news never activates detection or response rules. " + _text(status.get("error", ""), 200)
        ))
        self._show_news_checks(status, now)
        self._sync_news_motion()

    def _show_news_checks(self, status, now):
        if not isinstance(status, dict):
            status = {}
        checks = ["Any-source last successful feed check: "
                  + _news_checked_text(status.get("last_refresh"), now)]
        if _news_stamp(status.get("last_attempt"), now) is not None:
            checks.append("Last attempt: " + _news_checked_text(status["last_attempt"], now))
        if self._news_items:
            item = self._news_items[self._news_index]
            if item.get("origin") == "bundled-reference":
                checks.append("Bundled reference review: " + REFERENCE_REVIEWED + " (no live check)")
            else:
                checks.append("Selected headline cache confirmed: "
                              + _news_checked_text(item.get("verified_at"), now)
                              + " · " + _news_age_text(item.get("verified_at"), now))
        if status.get("error"):
            checks.append("Latest refresh error: " + _text(status["error"], 120))
        if self._news_refreshing and status.get("queued_reason"):
            checks.append(_text(status["queued_reason"], 180))
        self.news_checks.setText(" · ".join(checks))
        sources = status.get("sources")
        sources = sources if isinstance(sources, dict) else {}
        details = []
        for name, label in NEWS_SOURCE_LABELS.items():
            row = sources.get(name)
            row = row if isinstance(row, dict) else {}
            state = _text(row.get("state", "not checked this session"), 60)
            text = f"{label}: {state}"
            count = row.get("items")
            if type(count) is int and 0 <= count <= MAX_NEWS_ITEMS:
                text += f" · {count} eligible headline(s)"
            stamp = _news_stamp(row.get("checked_at"), now)
            if stamp is not None:
                kind = "successful check" if state == "available" else "attempt"
                text += f" · {kind} " + _news_checked_text(stamp, now)
            if row.get("error"):
                text += " · " + _text(row["error"], 100)
            if row.get("reason"):
                text += " · " + _text(row["reason"], 120)
            details.append(text)
        self.news_sources.setText(" | ".join(details))

    def _show_news_headline(self) -> None:
        if not self._news_items:
            return
        item = self._news_items[self._news_index]
        source = NEWS_SOURCE_LABELS[item["source"]]
        date = datetime.fromtimestamp(item["published"], timezone.utc).strftime("%Y-%m-%d")
        kind = "REFERENCE" if item.get("origin") == "bundled-reference" else "STALE CACHE" if item.get("stale") else "CACHED INTEL"
        if item.get("content_kind") == "publisher-news" and item.get("origin") != "bundled-reference":
            kind = "STALE NEWS" if item.get("stale") else "CACHED NEWS"
        self.news_badge.setText(f"{kind} {self._news_index + 1}/{len(self._news_items)}")
        self.news_headline.setText(item["title"].replace("&", "&&"))
        self.news_headline.setAccessibleName(item["title"])
        self.news_headline.setToolTip(_tooltip_text("View cached research details (no download)\n" + item["title"] + "\n" + item["url"]))
        self.news_headline.setEnabled(True)
        self.news_headline.adjustSize()
        self.news_source_button.setText(f"{source} · {date}")
        self.news_source_button.setToolTip(_tooltip_text(f"{source}\nPublished (UTC): " + datetime.fromtimestamp(item["published"], timezone.utc).isoformat() + "\n" + item["url"]))
        self.news_source_button.setVisible(True)
        summary = item.get("summary") or "The publisher supplied a headline only. Open the source for its full research context."
        preview = summary if len(summary) <= 280 else summary[:277].rsplit(" ", 1)[0] + "…"
        self.news_summary.setText(preview)
        self.news_summary.setToolTip(_tooltip_text(_text(summary, MAX_NEWS_SUMMARY)))
        self.news_scroll.horizontalScrollBar().setValue(0)
        self._show_news_checks(self._snapshot.get("news_status"), time.time())
        self._reflow_page()

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
        visible = not self._closed and self._presentation_visible()
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
        if self._news_refreshing:
            self.status.setText("Official news refresh is already queued or running.")
            return
        settings = self._snapshot.get("settings") or {}
        if settings.get("spyware_network_enabled", getattr(self.config, "spyware_network_enabled", False)) is not True:
            self.status.setText("Enable research network access in Policy / Beacon before refreshing news.")
            self._open_news_settings()
            return
        if self._command("request_news_refresh"):
            self._news_activity = self._activities.begin("official-news", "Official news refresh queued…")
            self._news_refreshing = True
            self.news_refresh_button.setEnabled(False)
            self.news_pause_button.setEnabled(True)
            if not self._news_items:
                self._news_message("Official research headline refresh queued…")
            self._sync_news_motion()
            self.status.setText("Official news refresh queued. Headlines remain advisory research.")
        else:
            self.status.setText("News refresh was not queued. Enable network ingestion and check pending work.")

    def _open_news_settings(self) -> None:
        for index in range(self.tabs.count()):
            if self.tabs.tabText(index) == "Policy / Beacon":
                self.tabs.setCurrentIndex(index)
                self.setting_checks["spyware_network_enabled"].setFocus()
                break

    def _open_news_article(self) -> None:
        if not self._news_items:
            return
        self._open_news_url(self._news_items[self._news_index])

    def _open_news_url(self, item: dict) -> None:
        try:
            url = safe_news_article_url(item["url"], item["source"])
        except (ValueError, TypeError, UnicodeError):
            return
        QDesktopServices.openUrl(QUrl(url))

    def _open_news_details(self) -> None:
        """Render a bounded cached snapshot; opening this dialog never fetches."""
        if not self._news_items:
            return
        if self._news_dialog is not None:
            self._news_dialog.close()
            self._news_dialog.deleteLater()
        dialog = self._news_dialog = QDialog(self)
        dialog.setWindowTitle("SpywareGuard · Intelligence brief")
        available = self.screen().availableGeometry()
        dialog.resize(min(760, max(360, available.width() - 64)), min(480, max(300, available.height() - 64)))
        layout = QVBoxLayout(dialog)
        choices = QComboBox()
        choices.setMinimumWidth(0)
        choices.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        choices.setMinimumContentsLength(30)
        items = [dict(item) for item in self._news_items[:MAX_NEWS_ITEMS]]
        for item in items:
            day = datetime.fromtimestamp(item["published"], timezone.utc).strftime("%Y-%m-%d")
            choices.addItem(f"{NEWS_SOURCE_LABELS[item['source']]} · {day} · {item['title']}")
        layout.addWidget(choices)
        detail = QPlainTextEdit()
        detail.setReadOnly(True)
        layout.addWidget(detail, 1)
        self.news_detail = detail
        actions = QHBoxLayout()
        source_button = QPushButton("Open source in browser")
        self.news_detail_source_button = source_button
        actions.addWidget(source_button)
        close = QPushButton("Close")
        close.clicked.connect(dialog.close)
        actions.addWidget(close)
        layout.addLayout(actions)

        def render(index):
            item = items[index]
            label = "Bundled reference; not live news" if item.get("origin") == "bundled-reference" else (
                "Stale cached headline; refresh has not confirmed current status" if item.get("stale") else "Cached official-feed headline")
            if item.get("content_kind") == "publisher-news":
                label += " · publisher news/update, not a new technical research report"
            published = datetime.fromtimestamp(item["published"], timezone.utc).isoformat()
            checked = datetime.fromtimestamp(item["verified_at"], timezone.utc).isoformat()
            hits = len(self._rows(self._snapshot.get("hits")))
            responses = len(self._rows(self._snapshot.get("containments")))
            detail.setPlainText(
                f"{item['title']}\n\n{label}\nSource: {NEWS_SOURCE_LABELS[item['source']]}\n"
                f"Published: {published}\nReference review / feed check: {checked}\n{item['url']}\n\n"
                f"{_text(item.get('summary'), MAX_NEWS_SUMMARY) or 'No feed summary supplied; consult the original source.'}\n\n"
                f"Local dashboard context: {hits} recent hit records; {responses} response records.\n"
                "These counts do not connect this computer to the reported campaign. News is advisory research; "
                "it never approves an indicator, changes a rule, or authorizes containment. "
                "A cached brief cannot establish whether this host is compromised."
            )
            source_button.setProperty("news_item", item)

        choices.currentIndexChanged.connect(render)
        source_button.clicked.connect(lambda: self._open_news_url(source_button.property("news_item")))
        choices.setCurrentIndex(self._news_index)
        render(choices.currentIndex())
        dialog.show()
        dialog.raise_()

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
        self.coverage.setUndoRedoEnabled(False)
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

    def _build_definitions(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_label(
            "Import a local JSON definition pack, review its version and indicators, "
            "then activate that exact pack. Active definitions use the existing "
            "automatic containment policy without per-incident prompts."
        ))
        self.definitions_status = _label("Definition status is not available yet.")
        layout.addWidget(self.definitions_status)
        self.definitions_active = _label("Active pack: none")
        self.definitions_staged = _label("Imported preview: none")
        self.definitions_previous = _label("Previous pack: none")
        for label in (self.definitions_active, self.definitions_staged, self.definitions_previous):
            layout.addWidget(label)
        self.definitions_preview = QPlainTextEdit()
        self.definitions_preview.setReadOnly(True)
        self.definitions_preview.setUndoRedoEnabled(False)
        self.definitions_preview.setMaximumHeight(160)
        self.definitions_preview.setPlaceholderText("The validated pack's first 25 literal indicators appear here.")
        layout.addWidget(self.definitions_preview)
        self.import_definitions_button = QPushButton("Import definitions…")
        self.activate_definitions_button = QPushButton("Activate imported pack")
        self.rollback_definitions_button = QPushButton("Roll back to previous pack")
        self.import_definitions_button.clicked.connect(self._import_definitions)
        self.activate_definitions_button.clicked.connect(self._activate_definitions)
        self.rollback_definitions_button.clicked.connect(self._rollback_definitions)
        layout.addLayout(self._tab_actions(page, self.import_definitions_button,
                                          self.activate_definitions_button,
                                          self.rollback_definitions_button))
        layout.addWidget(_label(
            "Packs contain literal SHA-256, IP and domain indicators. Importing only "
            "creates a preview. Activation is a local authorization; an integrity "
            "digest does not verify an external publisher. Research headlines and "
            "report imports remain separate from active definitions."
        ))
        layout.addStretch(1)
        self.tabs.addTab(page, "Definitions")

    @staticmethod
    def _definition_summary(title: str, value) -> str:
        if not isinstance(value, dict):
            return title + ": none"
        counts = value.get("counts") if isinstance(value.get("counts"), dict) else {}
        return (
            f"{title}: {_text(value.get('version'), 80)} · "
            f"{_text(value.get('indicator_count', 0), 20)} indicators "
            f"(SHA-256 {_text(counts.get('sha256', 0), 20)}, "
            f"IP {_text(counts.get('ip', 0), 20)}, "
            f"domain {_text(counts.get('domain', 0), 20)})\n"
            f"Published: {_time_text(value.get('published_at'))} · "
            f"Expires: {_time_text(value.get('expires_at'))}\n"
            f"Digest: {_text(value.get('sha256'), 64)}"
        )

    def _update_definitions(self, value) -> None:
        data = value if isinstance(value, dict) else {}
        module = self._module()
        busy = data.get("busy") is True
        supported = callable(getattr(module, "queue_definition_import", None))
        self.definitions_active.setText(self._definition_summary("Active pack", data.get("active")))
        self.definitions_staged.setText(self._definition_summary("Imported preview", data.get("staged")))
        self.definitions_previous.setText(self._definition_summary("Previous pack", data.get("previous")))
        preview_pack = data.get("staged") or data.get("active")
        if isinstance(preview_pack, dict):
            rows = preview_pack.get("indicator_preview")
            rows = rows[:25] if isinstance(rows, (list, tuple)) else []
            rendered = [f"Showing {len(rows)} of {_text(preview_pack.get('indicator_count', 0), 20)} indicators"]
            rendered.extend(f"{_text(row.get('kind'), 16)}: {_text(row.get('value'), 253)}"
                            for row in rows if isinstance(row, dict))
            preview_text = "\n".join(rendered)
        else:
            preview_text = ""
        self._set_plain_text(self.definitions_preview, preview_text)
        message = "Definitions: " + _text(data.get("state", "not initialized"), 100)
        if busy:
            message += " · update queued or running"
        if data.get("error"):
            message += " · " + _text(data["error"], 500)
        self.definitions_status.setText(message)
        staged = data.get("staged")
        previous = data.get("previous")
        self.import_definitions_button.setEnabled(supported and not busy)
        self.activate_definitions_button.setEnabled(
            supported and not busy and isinstance(staged, dict)
            and type(staged.get("review_identity")) is dict
        )
        self.rollback_definitions_button.setEnabled(
            supported and not busy and isinstance(previous, dict)
            and type(previous.get("review_identity")) is dict
        )

    def _import_definitions(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, "Import spyware definitions", "", "JSON definition packs (*.json)",
        )
        if not path:
            return
        # File custody, parsing and persistence belong to the module worker.
        queued = self._command("queue_definition_import", path)
        self.definitions_status.setText(
            "Definition import queued; the validated preview will appear here."
            if queued else "Definition import was not queued; check module health."
        )

    def _definition_action(self, section: str, command: str) -> None:
        data = self._snapshot.get("definitions")
        row = data.get(section) if isinstance(data, dict) else None
        expected = row.get("review_identity") if isinstance(row, dict) else None
        if type(expected) is not dict:
            self.definitions_status.setText("Definition selection is stale; refresh the preview.")
            return
        queued = self._command(command, expected=copy.deepcopy(expected))
        self.definitions_status.setText(
            "Definition update queued; the active version changes after validation and persistence."
            if queued else "Definition update was not queued; refresh and check module health."
        )

    def _activate_definitions(self) -> None:
        self._definition_action("staged", "activate_definitions")

    def _rollback_definitions(self) -> None:
        self._definition_action("previous", "rollback_definitions")

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
        self.approve_button = QPushButton("Approve selected indicator")
        self.reject_button = QPushButton("Deactivate selected indicator")
        self.approve_button.clicked.connect(lambda: self._review_indicator(True))
        self.reject_button.clicked.connect(lambda: self._review_indicator(False))
        layout.addLayout(self._tab_actions(page, self.approve_button, self.reject_button))
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
        self._fit_choice(self.sandbox_scenario)
        layout.addWidget(self.sandbox_scenario)
        self.sandbox_button = QPushButton("Run offline rehearsal")
        self.sandbox_button.clicked.connect(self._run_sandbox)
        layout.addWidget(self.sandbox_button)
        self.sandbox_results = QPlainTextEdit()
        self.sandbox_results.setReadOnly(True)
        self.sandbox_results.setUndoRedoEnabled(False)
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
        self._fit_choice(self.guide_choice)
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

    @staticmethod
    def _fit_choice(choice) -> None:
        # The native popup retains every full caption; its selected caption is
        # also available literally by tooltip without widening every tab.
        choice.setMinimumContentsLength(12)
        choice.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        choice.setMinimumWidth(0)
        choice.currentTextChanged.connect(lambda text: choice.setToolTip(_tooltip_text(text)))
        choice.setToolTip(_tooltip_text(choice.currentText()))

    def _tab_actions(self, page, *buttons):
        grid = QGridLayout()
        for index, button in enumerate(buttons):
            grid.addWidget(button, index, 0)
        self._tab_action_rows.append((page, grid, buttons))
        return grid

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
        self._update_definitions(self._snapshot.get("definitions"))

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
        result = self.priority_scan.start()
        self.status.setText("Selected spyware checks scheduled." if result else "Scan was not scheduled; check selected scanners or pending work.")

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
        expected = item.get("review_identity")
        if type(expected) is not dict:
            self.status.setText("Indicator review is stale. Refresh and select the current evidence again.")
            return
        if self._command("review_indicator", kind, value, approved=approved, expected=expected):
            self.status.setText("Indicator review queued; applied state will appear in the next snapshot.")
        else:
            self.status.setText("Indicator review was not queued. Refresh the evidence and check module health.")

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
        if self._closed or not self._presentation_visible():
            return
        self._update_availability()
        module = self._module()
        if module is None:
            self._update_news({})
            return
        try:
            snapshot = module.dashboard_snapshot()
        except Exception:
            self.status.setText("SpywareGuard snapshot unavailable; the previous view is retained.")
            return
        if not isinstance(snapshot, dict):
            return
        self._snapshot = snapshot
        self._update_definitions(snapshot.get("definitions"))
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
        self._set_plain_text(self.coverage, _details_text(coverage))
        beacon = snapshot.get("beacon") or {}
        self.beacon_status.setText(_text(beacon, 2_000))
        sandbox = snapshot.get("sandbox", snapshot.get("sandbox_results", []))
        if sandbox:
            self._set_plain_text(self.sandbox_results, _details_text(sandbox))
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
            review = snapshot.get("indicator_review")
            if isinstance(review, dict) and review.get("state") == "stale-review":
                self.status.setText("Indicator review is stale. Refresh and select the current evidence again.")

    def _set_plain_text(self, editor, text):
        if self._plain_text_rendered.get(editor) != text:
            _set_document_text(editor, text)
            self._plain_text_rendered[editor] = text

    @staticmethod
    def _rows(value) -> list[dict]:
        if not isinstance(value, (list, tuple)):
            return []
        return [row for row in value[:_ROW_LIMIT] if isinstance(row, dict)]

    def _fill(self, table: QTableWidget, rows: list[dict], columns) -> None:
        # Build one bounded immutable cell projection before touching Qt. The
        # current snapshot and complete evidence records still refresh each time;
        # a changed non-displayed field must still invalidate exact selection.
        rendered_rows = []
        for row in rows:
            cells = []
            for keys in columns:
                value = next((row[key] for key in keys if row.get(key) is not None), "")
                if keys == ("approved",):
                    value = "Approved" if value else "Inactive / review required"
                cells.append(_time_text(value) if keys[0] == "timestamp" else _text(value))
            rendered_rows.append(tuple(cells))
        rendered_rows = tuple(rendered_rows)
        previous_rows = self._table_rows.get(table, [])
        if self._table_rendered.get(table) == rendered_rows and previous_rows == rows:
            self._table_rows[table] = rows
            return
        # Retain selection by its complete bounded evidence record, not row index.
        selected = table.currentRow()
        previous = previous_rows[selected] if 0 <= selected < len(previous_rows) else None
        table.blockSignals(True)
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(len(rows))
            self._table_rows[table] = rows
            for row_index, cells in enumerate(rendered_rows):
                for column, rendered in enumerate(cells):
                    item = table.item(row_index, column)
                    if item is None:
                        item = QTableWidgetItem(rendered)
                        table.setItem(row_index, column, item)
                    elif item.text() != rendered:
                        item.setText(rendered)
                    tooltip = _tooltip_text(rendered)
                    if item.toolTip() != tooltip:
                        item.setToolTip(tooltip)
            if previous in rows:
                table.selectRow(rows.index(previous))
            elif previous is not None:
                table.clearSelection()
                table.setCurrentItem(None)
            self._table_rendered[table] = rendered_rows
        finally:
            table.setUpdatesEnabled(True)
            table.blockSignals(False)

    def _show_evidence(self, table: QTableWidget) -> None:
        rows = self._table_rows.get(table, [])
        row = table.currentRow()
        if 0 <= row < len(rows):
            self.evidence_detail.setPlainText(json.dumps(rows[row], indent=2, ensure_ascii=False, default=str)[:16_000])

    def _presentation_visible(self):
        window = self.window()
        return self.isVisible() and window.isVisible() and not window.isMinimized()

    def _watch_presentation_window(self):
        window = self.window()
        if window is not self._presentation_window:
            previous = self._presentation_window
            if previous is not None and previous is not self and isValid(previous):
                previous.removeEventFilter(self)
            self._presentation_window = window
            if window is not self:
                window.installEventFilter(self)

    def eventFilter(self, watched, event):  # noqa: N802
        if not isValid(self) or getattr(self, "_closed", True):
            return False
        if watched is self._presentation_window and event.type() == QEvent.Type.WindowStateChange:
            if self._presentation_visible():
                self.refresh()
            self._sync_news_motion()
        return False

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._watch_presentation_window()
        if not self._closed:
            self.refresh()
            self._timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        self._activities.close()
        self._news_activity = None
        self._news_rotation_timer.stop()
        self._news_scroll_timer.stop()
        self.news_spinner.set_active(self._news_refreshing, False)
        super().hideEvent(event)

    def _reflow_page(self) -> None:
        if not hasattr(self, "news_refresh_button") or getattr(self, "_reflowing_page", False):
            return
        self._reflowing_page = True
        try:
            for widget in (self.scan_button, self.news_headline, self.news_pause_button,
                           self.news_refresh_button, self.news_source_button, self.news_settings_button):
                widget.ensurePolished()
            margins = self.layout().contentsMargins()
            width = self.contentsRect().width()
            if self.parentWidget() is not None:
                width = min(width, self.parentWidget().contentsRect().width())
            available = max(0, width - margins.left() - margins.right())
            if hasattr(self, "tabs"):
                # QTabWidget includes hidden pages in its minimum. Reflow
                # their action rows against the actual page allowance too.
                frame = self.tabs.style().pixelMetric(QStyle.PixelMetric.PM_DefaultFrameWidth) * 2
                for page, grid, buttons in self._tab_action_rows:
                    row_margins = page.layout().contentsMargins()
                    row_width = max(0, available - frame - row_margins.left() - row_margins.right())
                    gap = max(0, grid.horizontalSpacing())
                    for button in buttons:
                        button.ensurePolished()
                    widths = [button.minimumSizeHint().width() for button in buttons]
                    columns = 1
                    for count in range(len(buttons), 0, -1):
                        if (sum(max(widths[column::count]) for column in range(count))
                                + gap * (count - 1) <= row_width):
                            columns = count
                            break
                    if self._tab_action_columns.get(grid) != columns:
                        self._tab_action_columns[grid] = columns
                        for button in buttons:
                            grid.removeWidget(button)
                        for column in range(grid.columnCount()):
                            grid.setColumnStretch(column, 0)
                        for index, button in enumerate(buttons):
                            grid.addWidget(button, index // columns, index % columns)
                        grid.setColumnStretch(columns, 1)
            gap = max(0, self._header_grid.horizontalSpacing())
            title_width = self._page_title.fontMetrics().averageCharWidth() * 28
            stacked = available < self.scan_button.minimumSizeHint().width() + title_width + gap
            if stacked != getattr(self, "_header_stacked", None):
                self._header_stacked = stacked
                self._header_grid.removeWidget(self.scan_button)
                self._header_grid.addWidget(self.scan_button, 1 if stacked else 0, 0 if stacked else 1)

            margins = self._news_grid.contentsMargins()
            # A stale minimum can temporarily expand the strip beyond its
            # viewport. Never use that expanded geometry to choose more columns
            # and perpetuate horizontal overflow after a font/width change.
            news_width = min(available, self.news_strip.contentsRect().width())
            available = max(0, news_width - margins.left() - margins.right())
            buttons = tuple(button for button in (self.news_source_button, self.news_pause_button,
                                                   self.news_refresh_button, self.news_settings_button)
                            if not button.isHidden())
            gap = max(0, self._news_action_grid.horizontalSpacing())
            widths = [button.minimumSizeHint().width() for button in buttons]
            action_width = sum(widths) + gap * max(0, len(widths) - 1)
            headline_width = self.news_headline.fontMetrics().averageCharWidth() * 24
            stacked = available < self._news_identity.minimumSizeHint().width() + headline_width + action_width + gap * 2
            columns = max(1, len(buttons))
            if stacked:
                for count in range(len(buttons), 0, -1):
                    if (sum(max(widths[column::count]) for column in range(count))
                            + gap * (count - 1) <= available):
                        columns = count
                        break
                else:
                    columns = 1
            key = (stacked, columns, buttons)
            if key != getattr(self, "_news_layout_key", None):
                self._news_layout_key = key
                for widget in (self._news_identity, self.news_scroll, self._news_actions):
                    self._news_grid.removeWidget(widget)
                self._news_grid.addWidget(self._news_identity, 0, 0)
                self._news_grid.addWidget(self.news_scroll, 0, 1)
                self._news_grid.addWidget(self._news_actions, 1 if stacked else 0,
                                          0 if stacked else 2, 1, 2 if stacked else 1)
                for button in (self.news_source_button, self.news_pause_button,
                               self.news_refresh_button, self.news_settings_button):
                    self._news_action_grid.removeWidget(button)
                for column in range(self._news_action_grid.columnCount()):
                    self._news_action_grid.setColumnStretch(column, 0)
                for index, button in enumerate(buttons):
                    self._news_action_grid.addWidget(button, index // columns, index % columns)
                self._news_action_grid.setColumnStretch(columns, 1)
            self.news_scroll.setFixedHeight(max(self.news_headline.sizeHint().height(),
                                                 self.news_badge.sizeHint().height()))
        finally:
            self._reflowing_page = False

    def event(self, event):
        result = super().event(event)
        if event.type() == QEvent.Type.ParentChange and hasattr(self, "_presentation_window"):
            self._watch_presentation_window()
        if event.type() == QEvent.Type.WindowStateChange and not self._closed:
            if self._presentation_visible():
                self.refresh()
            self._sync_news_motion()
        if event.type() in (QEvent.Type.LayoutRequest, QEvent.Type.FontChange, QEvent.Type.StyleChange):
            self._reflow_page()
        return result

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._reflow_page()
        if hasattr(self, "news_spinner"):
            self._sync_news_motion()

    def closeEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        self._activities.close()
        self._news_activity = None
        self._closed = True
        self._sync_news_motion()
        if self._lab_dialog is not None:
            self._lab_dialog.close()
        if self._news_dialog is not None:
            self._news_dialog.close()
        super().closeEvent(event)
